module Tests.DiscoveryTests

open Expecto
open Elmish.OIDC
open Elmish.OIDC.Types
open Tests.Helpers
open Thoth.Json.Net

let private validDiscoveryJson =
    Encode.object [
        "issuer", Encode.string "https://auth.example.com"
        "authorization_endpoint", Encode.string "https://auth.example.com/authorize"
        "token_endpoint", Encode.string "https://auth.example.com/token"
        "userinfo_endpoint", Encode.string "https://auth.example.com/userinfo"
        "jwks_uri", Encode.string "https://auth.example.com/.well-known/jwks.json"
        "end_session_endpoint", Encode.string "https://auth.example.com/logout"
    ] |> Encode.toString 0

[<Tests>]
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

    testCaseAsync "fetchDiscovery accepts different issuer in response (Azure AD multi-tenant)" <|
        async {
            let mismatchedJson =
                Encode.object [
                    "issuer", Encode.string "https://login.microsoftonline.com/{tenantid}/v2.0"
                    "authorization_endpoint", Encode.string "https://auth.example.com/authorize"
                    "token_endpoint", Encode.string "https://auth.example.com/token"
                    "userinfo_endpoint", Encode.string "https://auth.example.com/userinfo"
                    "jwks_uri", Encode.string "https://auth.example.com/.well-known/jwks.json"
                ] |> Encode.toString 0

            let http = mockHttp (Map.ofList [
                "https://auth.example.com/.well-known/openid-configuration", mismatchedJson
            ])
            let! doc = Discovery.fetch http "https://auth.example.com"
            Expect.equal doc.issuer "https://login.microsoftonline.com/{tenantid}/v2.0" "should preserve discovered issuer"
        }
]
