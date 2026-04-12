module Tests.CryptoTests

open Fable.Mocha
open Fable.Core
open Elmish.OIDC
open Elmish.OIDC.Types

let private enc = ReactNative.encoding
let private cry = ReactNative.crypto

let tests = testList "Crypto" [

    testList "base64UrlEncode" [
        testCase "empty input produces empty string" <| fun _ ->
            let result = Crypto.base64UrlEncode enc [||]
            Expect.equal result "" "empty bytes should produce empty string"

        testCase "strips padding characters" <| fun _ ->
            let result1 = Crypto.base64UrlEncode enc [| 0uy |]
            let result2 = Crypto.base64UrlEncode enc [| 0uy; 1uy |]
            Expect.isFalse (result1.Contains("=")) "should not contain padding (1 byte)"
            Expect.isFalse (result2.Contains("=")) "should not contain padding (2 bytes)"

        testCase "replaces + with - and / with _" <| fun _ ->
            let result = Crypto.base64UrlEncode enc [| 0xFBuy; 0xFFuy; 0xFEuy |]
            Expect.isFalse (result.Contains("+")) "should not contain +"
            Expect.isFalse (result.Contains("/")) "should not contain /"

        testCase "known input produces expected output" <| fun _ ->
            let bytes = [| 72uy; 101uy; 108uy; 108uy; 111uy |]
            let result = Crypto.base64UrlEncode enc bytes
            Expect.equal result "SGVsbG8" "Hello bytes should encode to SGVsbG8"
    ]

    testList "base64UrlDecode" [
        testCase "roundtrip preserves data" <| fun _ ->
            let original = [| 0uy; 1uy; 2uy; 127uy; 128uy; 255uy |]
            let decoded = original |> Crypto.base64UrlEncode enc |> Crypto.base64UrlDecode enc
            Expect.equal decoded original "roundtrip should preserve all byte values"

        testCase "restores padding before decoding" <| fun _ ->
            let result = Crypto.base64UrlDecode enc "AA"
            Expect.equal result [| 0uy |] "should decode unpadded input"

        testCase "roundtrip with 32 random bytes" <| fun _ ->
            let original = Crypto.randomBytes cry 32
            let decoded = original |> Crypto.base64UrlEncode enc |> Crypto.base64UrlDecode enc
            Expect.equal decoded original "roundtrip should preserve 32 random bytes"
    ]

    testList "PKCE (RFC 7636)" [
        testCaseAsync "computeCodeChallenge matches RFC 7636 Appendix B test vector" <|
            async {
                let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                let! challenge = Crypto.computeCodeChallenge cry enc verifier
                Expect.equal challenge expected "S256 challenge should match RFC 7636 test vector"
            }

        testCaseAsync "code challenge output is base64url-encoded" <|
            async {
                let verifier = Crypto.generateCodeVerifier cry enc
                let! challenge = Crypto.computeCodeChallenge cry enc verifier
                Expect.isFalse (challenge.Contains("=")) "no padding"
                Expect.isFalse (challenge.Contains("+")) "no +"
                Expect.isFalse (challenge.Contains("/")) "no /"
            }
    ]

    testList "ReactNative.crypto RSA" [
        testCaseAsync "importRsaKey and rsaVerify roundtrip" <|
            async {
                let! (privateKey, jwksKey) = Tests.Helpers.generateTestKeyPair () |> Async.AwaitPromise
                let data : byte[] = Fable.Core.JsInterop.emitJsExpr "test data to sign" "new TextEncoder().encode($0)"
                let! signature =
                    Fable.Core.JsInterop.emitJsExpr
                        (privateKey, data)
                        "globalThis.crypto.subtle.sign('RSASSA-PKCS1-v1_5', $0, $1)"
                    |> Async.AwaitPromise
                let sigBytes : byte[] = Fable.Core.JsInterop.emitJsExpr signature "new Uint8Array($0)"
                let! key = cry.importRsaKey jwksKey
                let! valid = cry.rsaVerify key sigBytes data
                Expect.isTrue valid "signature should verify"
            }

        testCaseAsync "rsaVerify rejects tampered data" <|
            async {
                let! (privateKey, jwksKey) = Tests.Helpers.generateTestKeyPair () |> Async.AwaitPromise
                let data : byte[] = Fable.Core.JsInterop.emitJsExpr "original data" "new TextEncoder().encode($0)"
                let! signature =
                    Fable.Core.JsInterop.emitJsExpr
                        (privateKey, data)
                        "globalThis.crypto.subtle.sign('RSASSA-PKCS1-v1_5', $0, $1)"
                    |> Async.AwaitPromise
                let sigBytes : byte[] = Fable.Core.JsInterop.emitJsExpr signature "new Uint8Array($0)"
                let! key = cry.importRsaKey jwksKey
                let tamperedData : byte[] = Fable.Core.JsInterop.emitJsExpr "tampered data" "new TextEncoder().encode($0)"
                let! valid = cry.rsaVerify key sigBytes tamperedData
                Expect.isFalse valid "tampered data should not verify"
            }
    ]

    testList "ReactNative.encoding" [
        testCase "utf8 roundtrip" <| fun _ ->
            let text = "Hello, World!"
            let bytes = enc.utf8Encode text
            let decoded = enc.utf8Decode bytes
            Expect.equal decoded text "UTF-8 roundtrip should preserve text"

        testCase "base64 roundtrip" <| fun _ ->
            let original = [| 0uy; 127uy; 255uy; 42uy |]
            let decoded = original |> enc.base64Encode |> enc.base64Decode
            Expect.equal decoded original "base64 roundtrip should preserve bytes"
    ]
]
