module Tests.StorageTests

open Fable.Mocha
open Elmish.OIDC.Types
open Elmish.OIDC.Storage
open Tests.Helpers

let tests = testList "Storage" [

    testList "AuthState serialization" [
        testCase "saveAuthState then loadAuthState roundtrips all fields" <| fun _ ->
            let storage = MemoryStorage() :> IStorage
            let authState : AuthState =
                { state = "test-state"
                  nonce = "test-nonce"
                  codeVerifier = "test-verifier"
                  redirectUri = "https://app.example.com/callback" }
            saveAuthState storage authState
            let loaded = loadAuthState storage
            match loaded with
            | Some s ->
                Expect.equal s.state authState.state "state"
                Expect.equal s.nonce authState.nonce "nonce"
                Expect.equal s.codeVerifier authState.codeVerifier "codeVerifier"
                Expect.equal s.redirectUri authState.redirectUri "redirectUri"
            | None ->
                failwith "loadAuthState should return Some after save"

        testCase "loadAuthState removes stored state (one-time read anti-replay)" <| fun _ ->
            let storage = MemoryStorage() :> IStorage
            let authState : AuthState =
                { state = "test-state"
                  nonce = "test-nonce"
                  codeVerifier = "test-verifier"
                  redirectUri = "https://app.example.com/callback" }
            saveAuthState storage authState
            let _first = loadAuthState storage
            let second = loadAuthState storage
            Expect.isNone second "second load should return None (consumed)"

        testCase "loadAuthState from empty storage returns None" <| fun _ ->
            let storage = MemoryStorage() :> IStorage
            Expect.isNone (loadAuthState storage) "should return None from empty storage"
    ]

    testList "Session serialization" [
        testCase "saveSession then loadSession roundtrips all fields" <| fun _ ->
            let storage = MemoryStorage() :> IStorage
            let response : TokenResponse =
                { accessToken = "access-token-123"
                  idToken = "id-token-456"
                  tokenType = "Bearer"
                  expiresIn = 3600
                  scope = "openid profile" }
            saveSession storage response
            let loaded = loadSession storage
            match loaded with
            | Some r ->
                Expect.equal r.accessToken response.accessToken "accessToken"
                Expect.equal r.idToken response.idToken "idToken"
                Expect.equal r.tokenType response.tokenType "tokenType"
                Expect.equal r.expiresIn response.expiresIn "expiresIn"
                Expect.equal r.scope response.scope "scope"
            | None ->
                failwith "loadSession should return Some after save"

        testCase "loadSession from empty storage returns None" <| fun _ ->
            let storage = MemoryStorage() :> IStorage
            Expect.isNone (loadSession storage) "should return None from empty storage"

        testCase "loadSession ignores malformed JSON" <| fun _ ->
            let storage = MemoryStorage() :> IStorage
            (storage :> IStorage).setItem SessionKey "not valid json {"
            Expect.isNone (loadSession storage) "malformed JSON should return None"
    ]

    testList "clearAll" [
        testCase "clearAll removes both auth state and session" <| fun _ ->
            let storage = MemoryStorage() :> IStorage
            let authState : AuthState =
                { state = "test-state"
                  nonce = "test-nonce"
                  codeVerifier = "test-verifier"
                  redirectUri = "https://app.example.com/callback" }
            let response : TokenResponse =
                { accessToken = "access-token-123"
                  idToken = "id-token-456"
                  tokenType = "Bearer"
                  expiresIn = 3600
                  scope = "openid profile" }
            saveAuthState storage authState
            saveSession storage response
            clearAll storage
            Expect.isNone (loadAuthState storage) "auth state should be cleared"
            Expect.isNone (loadSession storage) "session should be cleared"
    ]
]
