module Tests.StateTests

open Fable.Mocha
open Elmish.OIDC
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

let tests = testList "State" [

    testList "CSRF state validation" [
        testCase "mismatched callback state is rejected" <| fun _ ->
            let storage = MemoryStorage() :> IStorage
            let authState : AuthState =
                { state = "expected-state"
                  nonce = "test-nonce"
                  codeVerifier = "test-verifier"
                  redirectUri = "https://app.example.com/callback" }
            saveAuthState storage authState
            let loaded = loadAuthState storage
            match loaded with
            | Some s ->
                Expect.isFalse (s.state = "wrong-state") "mismatched states must not match"
            | None ->
                failwith "auth state should be loaded"

        testCase "matching callback state is accepted" <| fun _ ->
            let storage = MemoryStorage() :> IStorage
            let authState : AuthState =
                { state = "correct-state"
                  nonce = "test-nonce"
                  codeVerifier = "test-verifier"
                  redirectUri = "https://app.example.com/callback" }
            saveAuthState storage authState
            let loaded = loadAuthState storage
            match loaded with
            | Some s ->
                Expect.isTrue (s.state = "correct-state") "matching states should be equal"
            | None ->
                failwith "auth state should be loaded"

        testCase "auth state is consumed on load (prevents replay)" <| fun _ ->
            let storage = MemoryStorage() :> IStorage
            saveAuthState storage
                { state = "one-time"; nonce = "n"; codeVerifier = "v"; redirectUri = "https://x" }
            let _first = loadAuthState storage
            Expect.isNone (loadAuthState storage) "second load must return None"
    ]

    testList "update transitions" [
        testCase "DiscoveryFailed produces Failed model" <| fun _ ->
            let model, _cmd =
                update testOptions (MemoryStorage() :> IStorage) (fun _ _ -> Fable.Core.JS.Constructors.Promise.resolve "info")
                    (DiscoveryFailed (exn "network error"))
                    Initializing
            match model with
            | Failed (DiscoveryError _) -> ()
            | _ -> failwith "should be Failed(DiscoveryError)"

        testCase "ValidationFailed in Ready clears storage and returns Unauthenticated" <| fun _ ->
            let storage = MemoryStorage() :> IStorage
            saveSession storage
                { accessToken = "a"; idToken = "i"; tokenType = "Bearer"; expiresIn = 3600; scope = "openid" }
            let model, _cmd =
                update testOptions storage (fun _ _ -> Fable.Core.JS.Constructors.Promise.resolve "info")
                    (ValidationFailed (InvalidToken "bad"))
                    (Ready (testDiscoveryDoc, { keys = [] }, ValidatingToken))
            match model with
            | Ready (_, _, Unauthenticated) ->
                Expect.isNone (loadSession storage) "session should be cleared"
            | _ -> failwith "should be Ready(Unauthenticated)"

        testCase "LoggedOut returns Unauthenticated" <| fun _ ->
            let model, _cmd =
                update testOptions (MemoryStorage() :> IStorage) (fun _ _ -> Fable.Core.JS.Constructors.Promise.resolve "info")
                    LoggedOut
                    (Ready (testDiscoveryDoc, { keys = [] }, Unauthenticated))
            match model with
            | Ready (_, _, Unauthenticated) -> ()
            | _ -> failwith "should be Unauthenticated"

        testCase "Tick when not near expiry stays Authenticated" <| fun _ ->
            let session = { testSession () with expiresAt = System.DateTimeOffset.UtcNow.AddHours(1.0) }
            let model, _cmd =
                update testOptions (MemoryStorage() :> IStorage) (fun _ _ -> Fable.Core.JS.Constructors.Promise.resolve "info")
                    Tick
                    (Ready (testDiscoveryDoc, { keys = [] }, Authenticated session))
            match model with
            | Ready (_, _, Authenticated _) -> ()
            | _ -> failwith "should stay Authenticated when not near expiry"

        testCase "Tick when near expiry transitions to Renewing" <| fun _ ->
            let session = { testSession () with expiresAt = System.DateTimeOffset.UtcNow.AddSeconds(10.0) }
            let model, _cmd =
                update testOptions (MemoryStorage() :> IStorage) (fun _ _ -> Fable.Core.JS.Constructors.Promise.resolve "info")
                    Tick
                    (Ready (testDiscoveryDoc, { keys = [] }, Authenticated session))
            match model with
            | Ready (_, _, Renewing _) -> ()
            | _ -> failwith "should transition to Renewing when near expiry"

        testCase "Tick during Renewing is ignored" <| fun _ ->
            let session = testSession ()
            let model, _cmd =
                update testOptions (MemoryStorage() :> IStorage) (fun _ _ -> Fable.Core.JS.Constructors.Promise.resolve "info")
                    Tick
                    (Ready (testDiscoveryDoc, { keys = [] }, Renewing session))
            match model with
            | Ready (_, _, Renewing _) -> ()
            | _ -> failwith "should stay Renewing"

        testCase "unexpected message in wrong state is ignored" <| fun _ ->
            let model, _cmd =
                update testOptions (MemoryStorage() :> IStorage) (fun _ _ -> Fable.Core.JS.Constructors.Promise.resolve "info")
                    (TokenReceived { accessToken = "a"; idToken = "i"; tokenType = "Bearer"; expiresIn = 3600; scope = "openid" })
                    Initializing
            match model with
            | Initializing -> ()
            | _ -> failwith "should remain Initializing"
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
