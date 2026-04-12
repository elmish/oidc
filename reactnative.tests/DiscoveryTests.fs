module Tests.DiscoveryTests

open Fable.Mocha
open Elmish.OIDC
open Elmish.OIDC.Types
open Tests.Helpers
open Thoth.Json

let private validDiscoveryJson =
    Encode.object [
        "issuer", Encode.string "https://auth.example.com"
        "authorization_endpoint", Encode.string "https://auth.example.com/authorize"
        "token_endpoint", Encode.string "https://auth.example.com/token"
        "userinfo_endpoint", Encode.string "https://auth.example.com/userinfo"
        "jwks_uri", Encode.string "https://auth.example.com/.well-known/jwks.json"
        "end_session_endpoint", Encode.string "https://auth.example.com/logout"
    ] |> Encode.toString 0

let tests = testList "Discovery" [

    testCaseAsync "fetchDiscovery parses valid response" <|
        async {
            let http = mockHttp (Map.ofList [
                "https://auth.example.com/.well-known/openid-configuration", validDiscoveryJson
            ])
            let! doc = Discovery.fetch http "https://auth.example.com"
            Expect.equal doc.issuer "https://auth.example.com" "issuer"
            Expect.equal doc.authorizationEndpoint "https://auth.example.com/authorize" "authorization_endpoint"
            Expect.equal doc.tokenEndpoint "https://auth.example.com/token" "token_endpoint"
            Expect.equal doc.jwksUri "https://auth.example.com/.well-known/jwks.json" "jwks_uri"
            Expect.equal doc.endSessionEndpoint (Some "https://auth.example.com/logout") "end_session_endpoint"
        }

    testCaseAsync "fetchDiscovery trims trailing slash from authority" <|
        async {
            let http = mockHttp (Map.ofList [
                "https://auth.example.com/.well-known/openid-configuration", validDiscoveryJson
            ])
            let! doc = Discovery.fetch http "https://auth.example.com/"
            Expect.equal doc.issuer "https://auth.example.com" "issuer"
        }

    testCaseAsync "fetchDiscovery rejects issuer mismatch" <|
        async {
            let mismatchedJson =
                Encode.object [
                    "issuer", Encode.string "https://evil.example.com"
                    "authorization_endpoint", Encode.string "https://auth.example.com/authorize"
                    "token_endpoint", Encode.string "https://auth.example.com/token"
                    "userinfo_endpoint", Encode.string "https://auth.example.com/userinfo"
                    "jwks_uri", Encode.string "https://auth.example.com/.well-known/jwks.json"
                ] |> Encode.toString 0

            let http = mockHttp (Map.ofList [
                "https://auth.example.com/.well-known/openid-configuration", mismatchedJson
            ])
            let! result =
                async {
                    try
                        let! _ = Discovery.fetch http "https://auth.example.com"
                        return Ok ()
                    with ex ->
                        return Error ex.Message
                }
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("Issuer mismatch")) "should report issuer mismatch"
            | Ok _ -> failwith "should fail on issuer mismatch"
        }
]
