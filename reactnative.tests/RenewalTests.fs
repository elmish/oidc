module Tests.RenewalTests

open Fable.Mocha
open Fable.Core
open Elmish.OIDC
open Elmish.OIDC.Types
open Tests.Helpers
open Thoth.Json

let tests = testList "Renewal" [

    testList "Renewal.refreshToken" [
        testCaseAsync "returns error when no stored session" <|
            async {
                let storage = MemoryStorage() :> Storage
                let plt = testPlatform storage
                let renewal = Renewal.refreshToken plt
                let jwks : Jwks = { keys = [] }
                let! result = renewal.renew testDiscoveryDoc testOptions jwks storage
                match result with
                | Error (InvalidToken msg) -> Expect.isTrue (msg.Contains("No stored session")) "should mention no session"
                | _ -> failwith "should return InvalidToken error"
            }

        testCaseAsync "returns error when no refresh token in stored session" <|
            async {
                let storage = MemoryStorage() :> Storage
                let response : TokenResponse =
                    { accessToken = "at"; idToken = "it"; tokenType = "Bearer"
                      expiresIn = 3600; scope = "openid"; refreshToken = None }
                Storage.StoredSession.save storage response
                let plt = testPlatform storage
                let renewal = Renewal.refreshToken plt
                let jwks : Jwks = { keys = [] }
                let! result = renewal.renew testDiscoveryDoc testOptions jwks storage
                match result with
                | Error (InvalidToken msg) -> Expect.isTrue (msg.Contains("No refresh token")) "should mention no refresh token"
                | _ -> failwith "should return InvalidToken error"
            }

        testCaseAsync "exchanges refresh token and validates new id_token" <|
            async {
                let! (privateKey, jwksKey) = generateTestKeyPair () |> Async.AwaitPromise
                let now = nowEpoch ()
                let headerJson = Encode.object [ "alg", Encode.string "RS256"; "kid", Encode.string "test-kid-1" ] |> Encode.toString 0
                let payloadJson =
                    Encode.object [
                        "iss", Encode.string testOptions.authority
                        "sub", Encode.string "user-123"
                        "aud", [ testOptions.clientId ] |> List.map Encode.string |> Encode.list
                        "exp", Encode.int64 (now + 3600L)
                        "iat", Encode.int64 (now - 10L)
                    ] |> Encode.toString 0
                let! newIdToken = signJwt privateKey headerJson payloadJson |> Async.AwaitPromise

                let tokenResponseJson =
                    Encode.object [
                        "access_token", Encode.string "new-at"
                        "id_token", Encode.string newIdToken
                        "token_type", Encode.string "Bearer"
                        "expires_in", Encode.int 3600
                        "scope", Encode.string "openid"
                        "refresh_token", Encode.string "new-rt"
                    ] |> Encode.toString 0

                let storage = MemoryStorage() :> Storage
                let storedResponse : TokenResponse =
                    { accessToken = "old-at"; idToken = "old-it"; tokenType = "Bearer"
                      expiresIn = 3600; scope = "openid"; refreshToken = Some "old-rt" }
                Storage.StoredSession.save storage storedResponse

                let http = mockHttp (Map.ofList [ testDiscoveryDoc.tokenEndpoint, tokenResponseJson ])
                let nav, _ = mockNavigation ()
                let plt = testPlatformWith storage http nav
                let renewal = Renewal.refreshToken plt
                let jwks : Jwks = { keys = [ jwksKey ] }
                let! result = renewal.renew testDiscoveryDoc testOptions jwks storage
                match result with
                | Ok (payload, response) ->
                    Expect.equal payload.sub "user-123" "sub from new token"
                    Expect.equal response.accessToken "new-at" "new access token"
                    Expect.equal response.refreshToken (Some "new-rt") "new refresh token"
                | Error err ->
                    failwith $"expected Ok but got Error: {err}"
            }
    ]

    testList "expirySubscription" [
        testCase "creates disposable interval" <| fun _ ->
            let mutable count = 0
            let dispatch _ = count <- count + 1
            let sub = Renewal.expirySubscription ReactNative.timer dispatch
            sub.Dispose()
    ]
]
