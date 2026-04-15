module Tests.StorageTests

open Fable.Mocha
open Elmish.OIDC
open Elmish.OIDC.Types
open Tests.Helpers

let tests = testList "Storage" [

    testList "AuthState serialization" [
        testCase "saveAuthState then loadAuthState roundtrips all fields" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            let authState : AuthState =
                { state = "test-state"
                  nonce = "test-nonce"
                  codeVerifier = "test-verifier"
                  redirectUri = "https://app.example.com/callback" }
            Storage.AuthState.save storage authState
            let loaded = Storage.AuthState.load storage
            match loaded with
            | Some s ->
                Expect.equal s.state authState.state "state"
                Expect.equal s.nonce authState.nonce "nonce"
                Expect.equal s.codeVerifier authState.codeVerifier "codeVerifier"
                Expect.equal s.redirectUri authState.redirectUri "redirectUri"
            | None ->
                failwith "loadAuthState should return Some after save"

        testCase "loadAuthState removes stored state (one-time read anti-replay)" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            let authState : AuthState =
                { state = "test-state"
                  nonce = "test-nonce"
                  codeVerifier = "test-verifier"
                  redirectUri = "https://app.example.com/callback" }
            Storage.AuthState.save storage authState
            let _first = Storage.AuthState.load storage
            let second = Storage.AuthState.load storage
            Expect.isNone second "second load should return None (consumed)"

        testCase "loadAuthState from empty storage returns None" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            Expect.isNone (Storage.AuthState.load storage) "should return None from empty storage"
    ]

    testList "Session serialization" [
        testCase "saveSession then loadSession roundtrips all fields" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            let response : TokenResponse =
                { accessToken = "access-token-123"
                  idToken = "id-token-456"
                  tokenType = "Bearer"
                  expiresIn = 3600
                  scope = "openid profile"
                  refreshToken = None }
            Storage.StoredSession.save storage response
            let loaded = Storage.StoredSession.load storage
            match loaded with
            | Some r ->
                Expect.equal r.accessToken response.accessToken "accessToken"
                Expect.equal r.idToken response.idToken "idToken"
                Expect.equal r.tokenType response.tokenType "tokenType"
                Expect.equal r.expiresIn response.expiresIn "expiresIn"
                Expect.equal r.scope response.scope "scope"
            | None ->
                failwith "loadSession should return Some after save"

        testCase "saveSession then loadSession roundtrips refreshToken" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            let response : TokenResponse =
                { accessToken = "at"; idToken = "it"; tokenType = "Bearer"
                  expiresIn = 3600; scope = "openid"; refreshToken = Some "rt-xyz" }
            Storage.StoredSession.save storage response
            let loaded = Storage.StoredSession.load storage
            match loaded with
            | Some r -> Expect.equal r.refreshToken (Some "rt-xyz") "refreshToken"
            | None -> failwith "should return Some"

        testCase "loadSession from empty storage returns None" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            Expect.isNone (Storage.StoredSession.load storage) "should return None from empty storage"

        testCase "clearAll removes both auth state and session" <| fun _ ->
            let storage = MemoryStorage() :> Storage
            Storage.AuthState.save storage
                { state = "s"; nonce = "n"; codeVerifier = "v"; redirectUri = "r" }
            Storage.StoredSession.save storage
                { accessToken = "a"; idToken = "i"; tokenType = "Bearer"
                  expiresIn = 3600; scope = "openid"; refreshToken = None }
            Storage.clearAll storage
            Expect.isNone (Storage.AuthState.load storage) "auth state should be cleared"
            Expect.isNone (Storage.StoredSession.load storage) "session should be cleared"
    ]

    testList "ReactNative.MemoryStorage" [
        testCase "getItem returns None for missing key" <| fun _ ->
            let storage = ReactNative.memoryStorage ()
            Expect.isNone (storage.getItem "nonexistent") "should return None"

        testCase "setItem then getItem roundtrips" <| fun _ ->
            let storage = ReactNative.memoryStorage ()
            storage.setItem "key" "value"
            Expect.equal (storage.getItem "key") (Some "value") "should return stored value"

        testCase "removeItem clears the key" <| fun _ ->
            let storage = ReactNative.memoryStorage ()
            storage.setItem "key" "value"
            storage.removeItem "key"
            Expect.isNone (storage.getItem "key") "should return None after remove"
    ]
]
