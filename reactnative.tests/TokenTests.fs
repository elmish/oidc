module Tests.TokenTests

open Fable.Mocha
open Fable.Core
open Elmish.OIDC
open Elmish.OIDC.Types
open Tests.Helpers
open Thoth.Json

let private enc = ReactNative.encoding

let private validHeader : JwtHeader =
    { alg = "RS256"; kid = "test-kid-1" }

let private validPayload () : JwtPayload =
    let now = nowEpoch ()
    { iss = testOptions.authority
      sub = "user-123"
      aud = [ testOptions.clientId ]
      exp = now + 3600L
      iat = now - 10L
      nonce = Some "test-nonce" }

let tests = testList "Token" [

    testList "decodeJwt" [
        testCase "valid JWT decodes header and payload" <| fun _ ->
            let payload = validPayload ()
            let jwt = buildTestJwt validHeader payload
            match Token.Jwt.decode enc jwt with
            | Ok (header, decoded) ->
                Expect.equal header.alg "RS256" "alg"
                Expect.equal header.kid "test-kid-1" "kid"
                Expect.equal decoded.iss testOptions.authority "iss"
                Expect.equal decoded.sub "user-123" "sub"
                Expect.equal decoded.aud [ testOptions.clientId ] "aud"
                Expect.equal decoded.nonce (Some "test-nonce") "nonce"
            | Error err ->
                failwith $"Expected Ok but got Error: {err}"

        testCase "rejects JWT with wrong number of segments" <| fun _ ->
            match Token.Jwt.decode enc "only.two" with
            | Error msg -> Expect.isTrue (msg.Contains("3 parts")) "should mention 3 parts"
            | Ok _ -> failwith "Expected error for malformed JWT"

        testCase "aud as single string decodes to list" <| fun _ ->
            let headerJson = """{"alg":"RS256","kid":"test-kid-1"}"""
            let now = nowEpoch ()
            let payloadJson = $"""{{"iss":"{testOptions.authority}","sub":"user-123","aud":"{testOptions.clientId}","exp":{now + 3600L},"iat":{now - 10L}}}"""
            let jwt = buildJwt headerJson payloadJson "sig"
            match Token.Jwt.decode enc jwt with
            | Ok (_, payload) ->
                Expect.equal payload.aud [ testOptions.clientId ] "single aud string should decode to list"
            | Error err ->
                failwith $"Expected Ok: {err}"

        testCase "optional nonce field absent decodes to None" <| fun _ ->
            let headerJson = """{"alg":"RS256","kid":"test-kid-1"}"""
            let now = nowEpoch ()
            let payloadJson = $"""{{"iss":"{testOptions.authority}","sub":"user-123","aud":"{testOptions.clientId}","exp":{now + 3600L},"iat":{now - 10L}}}"""
            let jwt = buildJwt headerJson payloadJson "sig"
            match Token.Jwt.decode enc jwt with
            | Ok (_, p) -> Expect.isNone p.nonce "missing nonce should be None"
            | Error err -> failwith $"Expected Ok: {err}"
    ]

    testList "validateClaims" [
        testCase "accepts valid claims" <| fun _ ->
            let now = nowEpoch ()
            let payload = validPayload ()
            let result = Token.Claims.validate testOptions (Some "test-nonce") now validHeader payload
            Expect.isOk result "valid claims should pass"

        testCase "rejects algorithm 'none' (algorithm confusion attack)" <| fun _ ->
            let header = { alg = "none"; kid = "test-kid-1" }
            let payload = validPayload ()
            let result = Token.Claims.validate testOptions (Some "test-nonce") (nowEpoch ()) header payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("not allowed")) "should reject alg=none"
            | Ok _ -> failwith "alg=none MUST be rejected"

        testCase "rejects issuer mismatch" <| fun _ ->
            let payload = { validPayload () with iss = "https://evil.example.com" }
            let result = Token.Claims.validate testOptions (Some "test-nonce") (nowEpoch ()) validHeader payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("Issuer mismatch")) "should report issuer mismatch"
            | Ok _ -> failwith "wrong issuer MUST be rejected"

        testCase "rejects audience mismatch" <| fun _ ->
            let payload = { validPayload () with aud = [ "wrong-client-id" ] }
            let result = Token.Claims.validate testOptions (Some "test-nonce") (nowEpoch ()) validHeader payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("Audience")) "should report audience mismatch"
            | Ok _ -> failwith "wrong audience MUST be rejected"

        testCase "rejects expired token beyond clock skew" <| fun _ ->
            let now = nowEpoch ()
            let payload = { validPayload () with exp = now - 600L; iat = now - 4200L }
            let result = Token.Claims.validate testOptions None now validHeader payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("expired")) "should report expiry"
            | Ok _ -> failwith "expired token MUST be rejected"

        testCase "accepts token expired within clock skew" <| fun _ ->
            let now = nowEpoch ()
            let payload = { validPayload () with exp = now - 100L; iat = now - 3700L }
            let result = Token.Claims.validate testOptions None now validHeader payload
            Expect.isOk result "token within clock skew should be accepted"

        testCase "rejects nonce mismatch" <| fun _ ->
            let payload = { validPayload () with nonce = Some "wrong-nonce" }
            let result = Token.Claims.validate testOptions (Some "expected-nonce") (nowEpoch ()) validHeader payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("Nonce mismatch")) "should report nonce mismatch"
            | Ok _ -> failwith "wrong nonce MUST be rejected"
    ]

    testList "validateAndVerify key lookup" [
        testCaseAsync "rejects token with unknown kid" <|
            async {
                let payload = validPayload ()
                let jwt = buildTestJwt validHeader payload
                let jwks : Jwks = { keys = [] }
                let plt = testPlatform (MemoryStorage() :> Storage)
                let! result = Token.IdToken.validate plt testOptions "test-nonce" (nowEpoch ()) jwks jwt
                match result with
                | Error msg -> Expect.isTrue (msg.Contains("kid")) "should mention kid"
                | Ok _ -> failwith "unknown kid should be rejected"
            }

        testCaseAsync "validates signature with matching key" <|
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
                        "nonce", Encode.string "test-nonce"
                    ] |> Encode.toString 0
                let! jwt = signJwt privateKey headerJson payloadJson |> Async.AwaitPromise
                let jwks : Jwks = { keys = [ jwksKey ] }
                let plt = testPlatform (MemoryStorage() :> Storage)
                let! result = Token.IdToken.validate plt testOptions "test-nonce" now jwks jwt
                match result with
                | Ok payload ->
                    Expect.equal payload.sub "user-123" "sub should match"
                | Error err ->
                    failwith $"Expected Ok: {err}"
            }

        testCaseAsync "rejects tampered JWT payload" <|
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
                        "nonce", Encode.string "test-nonce"
                    ] |> Encode.toString 0
                let! jwt = signJwt privateKey headerJson payloadJson |> Async.AwaitPromise
                // Tamper with the JWT
                let parts = jwt.Split('.')
                let tamperedPayloadJson =
                    Encode.object [
                        "iss", Encode.string testOptions.authority
                        "sub", Encode.string "evil-user"
                        "aud", [ testOptions.clientId ] |> List.map Encode.string |> Encode.list
                        "exp", Encode.int64 (now + 3600L)
                        "iat", Encode.int64 (now - 10L)
                        "nonce", Encode.string "test-nonce"
                    ] |> Encode.toString 0
                let tamperedPayload = jsonToBase64Url tamperedPayloadJson
                let tamperedJwt = $"{parts.[0]}.{tamperedPayload}.{parts.[2]}"
                let jwks : Jwks = { keys = [ jwksKey ] }
                let plt = testPlatform (MemoryStorage() :> Storage)
                let! result = Token.IdToken.validate plt testOptions "test-nonce" now jwks tamperedJwt
                match result with
                | Error msg -> Expect.isTrue (msg.Contains("Signature")) "should report signature failure"
                | Ok _ -> failwith "tampered JWT should be rejected"
            }
    ]
]
