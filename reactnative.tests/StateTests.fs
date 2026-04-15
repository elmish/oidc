module Tests.StateTests

open Fable.Mocha
open Elmish.OIDC
open Elmish.OIDC.Types
open Tests.Helpers

let private tryGetSession (model: Model<'info>) : Session<'info> option =
    match model with
    | Ready (_, _, Authenticated session)
    | Ready (_, _, Renewing session) -> Some session
    | _ -> None

let private isAuthenticated model = tryGetSession model |> Option.isSome
let private tryGetAccessToken model = tryGetSession model |> Option.map (fun s -> s.accessToken)

let private testSession () : Session<string> =
    { accessToken = "at-123"
      idToken = "it-456"
      tokenType = "Bearer"
      expiresAt = System.DateTimeOffset.UtcNow.AddHours(1.0)
      scope = "openid"
      claims = { iss = "https://auth.example.com"; sub = "user"; aud = ["client"]; exp = 0L; iat = 0L; nonce = None }
      userInfo = None }

let private updateWith (storage: Storage) msg model =
    let plt = testPlatform storage
    State.update plt testOptions (fun _ _ -> async { return "info" }) msg model

let tests = testList "State" [

    testList "CSRF state validation" [
        testCase "mismatched callback state is rejected" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            let authState : AuthState =
                { state = "expected-state"; nonce = "test-nonce"
                  codeVerifier = "test-verifier"; redirectUri = "https://app.example.com/callback" }
            Storage.AuthState.save storage authState
            let loaded = Storage.AuthState.load storage
            match loaded with
            | Some s -> Expect.isFalse (s.state = "wrong-state") "mismatched states must not match"
            | None -> failwith "auth state should be loaded"

        testCase "matching callback state is accepted" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            let authState : AuthState =
                { state = "correct-state"; nonce = "test-nonce"
                  codeVerifier = "test-verifier"; redirectUri = "https://app.example.com/callback" }
            Storage.AuthState.save storage authState
            let loaded = Storage.AuthState.load storage
            match loaded with
            | Some s -> Expect.isTrue (s.state = "correct-state") "matching states should be equal"
            | None -> failwith "auth state should be loaded"

        testCase "auth state is consumed on load (prevents replay)" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            Storage.AuthState.save storage
                { state = "one-time"; nonce = "n"; codeVerifier = "v"; redirectUri = "https://x" }
            let _first = Storage.AuthState.load storage
            Expect.isNone (Storage.AuthState.load storage) "second load must return None"
    ]

    testList "update transitions" [
        testCase "DiscoveryFailed produces Failed model" <| fun _ ->
            let model, _cmd =
                updateWith (MemoryStorage() :> Storage)
                    (DiscoveryFailed (exn "network error"))
                    Initializing
            match model with
            | Failed (DiscoveryError _) -> ()
            | _ -> failwith "should be Failed(DiscoveryError)"

        testCase "ValidationFailed in Ready clears storage and returns Unauthenticated" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            Storage.StoredSession.save storage
                { accessToken = "a"; idToken = "i"; tokenType = "Bearer"; expiresIn = 3600; scope = "openid"; refreshToken = None }
            let model, _cmd =
                updateWith storage
                    (ValidationFailed (InvalidToken "bad"))
                    (Ready (testDiscoveryDoc, { keys = [] }, ValidatingToken))
            match model with
            | Ready (_, _, Unauthenticated) ->
                Expect.isNone (Storage.StoredSession.load storage) "session should be cleared"
            | _ -> failwith "should be Ready(Unauthenticated)"

        testCase "AuthCallback in Redirecting state processes callback" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            let authState : AuthState =
                { state = "cb-state"; nonce = "cb-nonce"
                  codeVerifier = "cb-verifier"; redirectUri = "https://app.example.com/callback" }
            Storage.AuthState.save storage authState
            let model, _cmd =
                updateWith storage
                    (AuthCallback ("auth-code", "cb-state"))
                    (Ready (testDiscoveryDoc, { keys = [] }, Redirecting))
            match model with
            | Ready (_, _, ExchangingCode) -> ()
            | _ -> failwith "should transition to ExchangingCode"

        testCase "AuthCallback with mismatched state returns Unauthenticated" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            let authState : AuthState =
                { state = "expected-state"; nonce = "n"
                  codeVerifier = "v"; redirectUri = "https://app.example.com/callback" }
            Storage.AuthState.save storage authState
            let model, _cmd =
                updateWith storage
                    (AuthCallback ("code", "wrong-state"))
                    (Ready (testDiscoveryDoc, { keys = [] }, Redirecting))
            match model with
            | Ready (_, _, Unauthenticated) -> ()
            | _ -> failwith "should be Unauthenticated on state mismatch"

        testCase "LoggedOut returns Unauthenticated" <| fun _ ->
            let model, _cmd =
                updateWith (MemoryStorage() :> Storage)
                    LoggedOut
                    (Ready (testDiscoveryDoc, { keys = [] }, Unauthenticated))
            match model with
            | Ready (_, _, Unauthenticated) -> ()
            | _ -> failwith "should be Unauthenticated"

        testCase "Tick when not near expiry stays Authenticated" <| fun _ ->
            let session = { testSession () with expiresAt = System.DateTimeOffset.UtcNow.AddHours(1.0) }
            let model, _cmd =
                updateWith (MemoryStorage() :> Storage)
                    Tick
                    (Ready (testDiscoveryDoc, { keys = [] }, Authenticated session))
            match model with
            | Ready (_, _, Authenticated _) -> ()
            | _ -> failwith "should stay Authenticated when not near expiry"

        testCase "Tick when near expiry transitions to Renewing" <| fun _ ->
            let session = { testSession () with expiresAt = System.DateTimeOffset.UtcNow.AddSeconds(10.0) }
            let model, _cmd =
                updateWith (MemoryStorage() :> Storage)
                    Tick
                    (Ready (testDiscoveryDoc, { keys = [] }, Authenticated session))
            match model with
            | Ready (_, _, Renewing _) -> ()
            | _ -> failwith "should transition to Renewing when near expiry"

        testCase "Tick during Renewing is ignored" <| fun _ ->
            let session = testSession ()
            let model, _cmd =
                updateWith (MemoryStorage() :> Storage)
                    Tick
                    (Ready (testDiscoveryDoc, { keys = [] }, Renewing session))
            match model with
            | Ready (_, _, Renewing _) -> ()
            | _ -> failwith "should stay Renewing"
    ]

    testList "model query helpers" [
        testCase "Initializing has no session" <| fun _ ->
            Expect.isNone (tryGetSession (Initializing : Model<string>)) "no session"

        testCase "Failed has no session" <| fun _ ->
            Expect.isNone (tryGetSession (Failed (InvalidToken "test") : Model<string>)) "no session"

        testCase "Unauthenticated has no session" <| fun _ ->
            Expect.isNone (tryGetSession (Ready (testDiscoveryDoc, { keys = [] }, Unauthenticated) : Model<string>)) "no session"

        testCase "Authenticated exposes session" <| fun _ ->
            let model : Model<string> = Ready (testDiscoveryDoc, { keys = [] }, Authenticated (testSession ()))
            match tryGetSession model with
            | Some s -> Expect.equal s.accessToken "at-123" "access token"
            | None -> failwith "should return session"

        testCase "Renewing still exposes session" <| fun _ ->
            let model : Model<string> = Ready (testDiscoveryDoc, { keys = [] }, Renewing (testSession ()))
            Expect.isSome (tryGetSession model) "should have session during renewal"

        testCase "tryGetAccessToken returns token for Authenticated" <| fun _ ->
            let model : Model<string> = Ready (testDiscoveryDoc, { keys = [] }, Authenticated (testSession ()))
            Expect.equal (tryGetAccessToken model) (Some "at-123") "access token"

        testCase "isAuthenticated is false for Unauthenticated" <| fun _ ->
            let model : Model<string> = Ready (testDiscoveryDoc, { keys = [] }, Unauthenticated)
            Expect.isFalse (isAuthenticated model) "not authenticated"
    ]
]
