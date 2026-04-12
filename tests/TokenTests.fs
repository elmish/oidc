module Tests.TokenTests

open Fable.Mocha
open Fable.Core
open Elmish.OIDC
open Elmish.OIDC.Types
open Tests.Helpers
open Thoth.Json

let private enc = Browser.encoding
let private plt = testPlatform (MemoryStorage() :> Storage)

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
            match Token.decodeJwt enc jwt with
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
            match Token.decodeJwt enc "only.two" with
            | Error msg -> Expect.isTrue (msg.Contains("3 parts")) "should mention 3 parts"
            | Ok _ -> failwith "Expected error for malformed JWT"

        testCase "rejects single segment" <| fun _ ->
            match Token.decodeJwt enc "nodotsatall" with
            | Error _ -> ()
            | Ok _ -> failwith "Expected error for single segment"

        testCase "rejects four segments" <| fun _ ->
            match Token.decodeJwt enc "a.b.c.d" with
            | Error _ -> ()
            | Ok _ -> failwith "Expected error for four segments"

        testCase "aud as single string decodes to list" <| fun _ ->
            let headerJson = """{"alg":"RS256","kid":"test-kid-1"}"""
            let now = nowEpoch ()
            let payloadJson = $"""{{"iss":"{testOptions.authority}","sub":"user-123","aud":"{testOptions.clientId}","exp":{now + 3600L},"iat":{now - 10L}}}"""
            let jwt = buildJwt headerJson payloadJson "sig"
            match Token.decodeJwt enc jwt with
            | Ok (_, payload) ->
                Expect.equal payload.aud [ testOptions.clientId ] "single aud string should decode to list"
            | Error err ->
                failwith $"Expected Ok: {err}"

        testCase "aud as array with multiple entries" <| fun _ ->
            let headerJson = """{"alg":"RS256","kid":"test-kid-1"}"""
            let now = nowEpoch ()
            let payloadJson = $"""{{"iss":"{testOptions.authority}","sub":"user-123","aud":["{testOptions.clientId}","other-client"],"exp":{now + 3600L},"iat":{now - 10L}}}"""
            let jwt = buildJwt headerJson payloadJson "sig"
            match Token.decodeJwt enc jwt with
            | Ok (_, p) ->
                Expect.equal p.aud.Length 2 "should have two audiences"
                Expect.isTrue (p.aud |> List.contains testOptions.clientId) "should contain our client"
            | Error err -> failwith $"Expected Ok: {err}"

        testCase "optional nonce field absent decodes to None" <| fun _ ->
            let headerJson = """{"alg":"RS256","kid":"test-kid-1"}"""
            let now = nowEpoch ()
            let payloadJson = $"""{{"iss":"{testOptions.authority}","sub":"user-123","aud":"{testOptions.clientId}","exp":{now + 3600L},"iat":{now - 10L}}}"""
            let jwt = buildJwt headerJson payloadJson "sig"
            match Token.decodeJwt enc jwt with
            | Ok (_, p) -> Expect.isNone p.nonce "missing nonce should be None"
            | Error err -> failwith $"Expected Ok: {err}"
    ]

    testList "validateClaims" [

        testCase "accepts valid claims" <| fun _ ->
            let now = nowEpoch ()
            let header = validHeader
            let payload = validPayload ()
            let result = Token.validateClaims testOptions (Some "test-nonce") now header payload
            Expect.isOk result "valid claims should pass"

        testCase "rejects algorithm 'none' (algorithm confusion attack)" <| fun _ ->
            let header = { alg = "none"; kid = "test-kid-1" }
            let payload = validPayload ()
            let result = Token.validateClaims testOptions (Some "test-nonce") (nowEpoch ()) header payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("not allowed")) "should reject alg=none"
            | Ok _ -> failwith "alg=none MUST be rejected"

        testCase "rejects algorithm not in whitelist" <| fun _ ->
            let header = { alg = "RS384"; kid = "test-kid-1" }
            let payload = validPayload ()
            let result = Token.validateClaims testOptions (Some "test-nonce") (nowEpoch ()) header payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("not allowed")) "RS384 not in [RS256]"
            | Ok _ -> failwith "unlisted algorithm should be rejected"

        testCase "rejects issuer mismatch" <| fun _ ->
            let payload = { validPayload () with iss = "https://evil.example.com" }
            let result = Token.validateClaims testOptions (Some "test-nonce") (nowEpoch ()) validHeader payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("Issuer mismatch")) "should report issuer mismatch"
            | Ok _ -> failwith "wrong issuer MUST be rejected"

        testCase "normalizes issuer trailing slash" <| fun _ ->
            let opts = { testOptions with authority = "https://auth.example.com/" }
            let payload = validPayload ()
            let result = Token.validateClaims opts (Some "test-nonce") (nowEpoch ()) validHeader payload
            Expect.isOk result "trailing slash on authority should be trimmed"

        testCase "rejects audience mismatch" <| fun _ ->
            let payload = { validPayload () with aud = [ "wrong-client-id" ] }
            let result = Token.validateClaims testOptions (Some "test-nonce") (nowEpoch ()) validHeader payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("Audience")) "should report audience mismatch"
            | Ok _ -> failwith "wrong audience MUST be rejected"

        testCase "accepts when aud array contains client among others" <| fun _ ->
            let payload = { validPayload () with aud = [ "other"; testOptions.clientId; "another" ] }
            let result = Token.validateClaims testOptions (Some "test-nonce") (nowEpoch ()) validHeader payload
            Expect.isOk result "client present in aud array should pass"

        testCase "rejects expired token beyond clock skew" <| fun _ ->
            let now = nowEpoch ()
            let payload = { validPayload () with exp = now - 600L; iat = now - 4200L }
            let result = Token.validateClaims testOptions None now validHeader payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("expired")) "should report expiry"
            | Ok _ -> failwith "expired token MUST be rejected"

        testCase "accepts token expired within clock skew" <| fun _ ->
            let now = nowEpoch ()
            let payload = { validPayload () with exp = now - 100L; iat = now - 3700L }
            let result = Token.validateClaims testOptions None now validHeader payload
            Expect.isOk result "token within clock skew should be accepted"

        testCase "rejects future-dated iat beyond clock skew" <| fun _ ->
            let now = nowEpoch ()
            let payload = { validPayload () with iat = now + 600L }
            let result = Token.validateClaims testOptions (Some "test-nonce") now validHeader payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("future")) "should report future-dated"
            | Ok _ -> failwith "future-dated token MUST be rejected"

        testCase "accepts iat within clock skew" <| fun _ ->
            let now = nowEpoch ()
            let payload = { validPayload () with iat = now + 100L }
            let result = Token.validateClaims testOptions (Some "test-nonce") now validHeader payload
            Expect.isOk result "iat within clock skew should be accepted"

        testCase "rejects nonce mismatch" <| fun _ ->
            let payload = { validPayload () with nonce = Some "wrong-nonce" }
            let result = Token.validateClaims testOptions (Some "expected-nonce") (nowEpoch ()) validHeader payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("Nonce mismatch")) "should report nonce mismatch"
            | Ok _ -> failwith "wrong nonce MUST be rejected"

        testCase "rejects missing nonce when expected" <| fun _ ->
            let payload = { validPayload () with nonce = None }
            let result = Token.validateClaims testOptions (Some "expected-nonce") (nowEpoch ()) validHeader payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("Nonce")) "should report missing nonce"
            | Ok _ -> failwith "missing nonce when expected MUST be rejected"

        testCase "accepts missing nonce when not required" <| fun _ ->
            let payload = { validPayload () with nonce = None }
            let result = Token.validateClaims testOptions None (nowEpoch ()) validHeader payload
            Expect.isOk result "no nonce required -> should accept"

        testCase "checks run in priority order (alg before issuer)" <| fun _ ->
            let header = { alg = "none"; kid = "test-kid-1" }
            let payload = { validPayload () with iss = "https://evil.example.com" }
            let result = Token.validateClaims testOptions None (nowEpoch ()) header payload
            match result with
            | Error msg -> Expect.isTrue (msg.Contains("not allowed")) "alg check should come first"
            | Ok _ -> failwith "should fail"
    ]

    testList "validateAndVerify key lookup" [
        testCaseAsync "rejects token with unknown kid" <|
            async {
                let payload = validPayload ()
                let jwt = buildTestJwt validHeader payload
                let jwks : Jwks = { keys = [] }
                let! result = Token.validateIdToken plt testOptions "test-nonce" (nowEpoch ()) jwt jwks
                match result with
                | Error msg -> Expect.isTrue (msg.Contains("No signing key")) "should report missing key"
                | Ok _ -> failwith "unknown kid should fail"
            }

        testCaseAsync "rejects token with kid matching non-sig key" <|
            async {
                let payload = validPayload ()
                let jwt = buildTestJwt validHeader payload
                // Key exists but use = "enc" not "sig"
                let key : JwksKey = { kty = "RSA"; kid = "test-kid-1"; n = "abc"; e = "AQAB"; alg = "RS256"; ``use`` = "enc" }
                let jwks : Jwks = { keys = [ key ] }
                let! result = Token.validateIdToken plt testOptions "test-nonce" (nowEpoch ()) jwt jwks
                match result with
                | Error msg -> Expect.isTrue (msg.Contains("No signing key")) "should reject non-sig key"
                | Ok _ -> failwith "enc key should not be used for signatures"
            }

        testCaseAsync "valid signed token passes full pipeline" <|
            async {
                let! (privateKey, pubJwk) = generateTestKeyPair () |> Async.AwaitPromise
                let jwks : Jwks = { keys = [ pubJwk ] }
                let now = nowEpoch ()
                let nonce = "test-nonce-123"

                let headerJson = $"""{{"alg":"RS256","kid":"{pubJwk.kid}"}}"""
                let payloadJson =
                    Encode.object [
                        "iss", Encode.string testOptions.authority
                        "sub", Encode.string "user-123"
                        "aud", Encode.list [ Encode.string testOptions.clientId ]
                        "exp", Encode.int64 (now + 3600L)
                        "iat", Encode.int64 (now - 10L)
                        "nonce", Encode.string nonce
                    ] |> Encode.toString 0

                let! jwt = signJwt privateKey headerJson payloadJson |> Async.AwaitPromise
                let! result = Token.validateIdToken plt testOptions nonce now jwt jwks
                Expect.isOk result "valid signed token should pass"
            }

        testCaseAsync "tampered payload fails signature verification" <|
            async {
                let! (privateKey, pubJwk) = generateTestKeyPair () |> Async.AwaitPromise
                let jwks : Jwks = { keys = [ pubJwk ] }
                let now = nowEpoch ()
                let nonce = "test-nonce-123"

                let headerJson = $"""{{"alg":"RS256","kid":"{pubJwk.kid}"}}"""
                let payloadJson =
                    Encode.object [
                        "iss", Encode.string testOptions.authority
                        "sub", Encode.string "user-123"
                        "aud", Encode.list [ Encode.string testOptions.clientId ]
                        "exp", Encode.int64 (now + 3600L)
                        "iat", Encode.int64 (now - 10L)
                        "nonce", Encode.string nonce
                    ] |> Encode.toString 0

                let! jwt = signJwt privateKey headerJson payloadJson |> Async.AwaitPromise
                let parts = jwt.Split('.')
                let tamperedPayloadJson =
                    Encode.object [
                        "iss", Encode.string testOptions.authority
                        "sub", Encode.string "hacker"
                        "aud", Encode.list [ Encode.string testOptions.clientId ]
                        "exp", Encode.int64 (now + 3600L)
                        "iat", Encode.int64 (now - 10L)
                        "nonce", Encode.string nonce
                    ] |> Encode.toString 0
                let tamperedJwt = $"{parts.[0]}.{jsonToBase64Url tamperedPayloadJson}.{parts.[2]}"

                let! result = Token.validateIdToken plt testOptions nonce now tamperedJwt jwks
                match result with
                | Error msg -> Expect.isTrue (msg.Contains("Signature")) "should fail signature"
                | Ok _ -> failwith "tampered token should not validate"
            }

        testCaseAsync "revalidateStoredToken succeeds without nonce" <|
            async {
                let! (privateKey, pubJwk) = generateTestKeyPair () |> Async.AwaitPromise
                let jwks : Jwks = { keys = [ pubJwk ] }
                let now = nowEpoch ()

                let headerJson = $"""{{"alg":"RS256","kid":"{pubJwk.kid}"}}"""
                let payloadJson =
                    Encode.object [
                        "iss", Encode.string testOptions.authority
                        "sub", Encode.string "user-123"
                        "aud", Encode.list [ Encode.string testOptions.clientId ]
                        "exp", Encode.int64 (now + 3600L)
                        "iat", Encode.int64 (now - 10L)
                    ] |> Encode.toString 0

                let! jwt = signJwt privateKey headerJson payloadJson |> Async.AwaitPromise
                let! result = Token.revalidateStoredToken plt testOptions now jwt jwks
                Expect.isOk result "revalidation without nonce should succeed"
            }
    ]
]
