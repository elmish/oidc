module Tests.CryptoTests

open Expecto
open Elmish.OIDC
open Elmish.OIDC.Types

let private cry = DotNet.crypto

[<Tests>]
let tests = testList "Crypto" [

    testList "base64UrlEncode" [
        testCase "empty input produces empty string" <| fun _ ->
            let result = Crypto.Base64Url.encode [||]
            Expect.equal result "" "empty bytes should produce empty string"

        testCase "strips padding characters" <| fun _ ->
            let result1 = Crypto.Base64Url.encode [| 0uy |]
            let result2 = Crypto.Base64Url.encode [| 0uy; 1uy |]
            Expect.isFalse (result1.Contains("=")) "should not contain padding (1 byte)"
            Expect.isFalse (result2.Contains("=")) "should not contain padding (2 bytes)"

        testCase "replaces + with - and / with _" <| fun _ ->
            let result = Crypto.Base64Url.encode [| 0xFBuy; 0xFFuy; 0xFEuy |]
            Expect.isFalse (result.Contains("+")) "should not contain +"
            Expect.isFalse (result.Contains("/")) "should not contain /"

        testCase "known input produces expected output" <| fun _ ->
            let bytes = [| 72uy; 101uy; 108uy; 108uy; 111uy |]
            let result = Crypto.Base64Url.encode bytes
            Expect.equal result "SGVsbG8" "Hello bytes should encode to SGVsbG8"
    ]

    testList "base64UrlDecode" [
        testCase "roundtrip preserves data" <| fun _ ->
            let original = [| 0uy; 1uy; 2uy; 127uy; 128uy; 255uy |]
            let decoded = original |> Crypto.Base64Url.encode |> Crypto.Base64Url.decode
            Expect.equal decoded original "roundtrip should preserve all byte values"

        testCase "restores padding before decoding" <| fun _ ->
            let result = Crypto.Base64Url.decode "AA"
            Expect.equal result [| 0uy |] "should decode unpadded input"

        testCase "roundtrip with 32 random bytes" <| fun _ ->
            let original = Crypto.randomBytes cry 32
            let decoded = original |> Crypto.Base64Url.encode |> Crypto.Base64Url.decode
            Expect.equal decoded original "roundtrip should preserve 32 random bytes"
    ]

    testList "PKCE (RFC 7636)" [
        testCaseAsync "computeCodeChallenge matches RFC 7636 Appendix B test vector" <|
            async {
                let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                let! challenge = Crypto.CodeChallenge.compute cry verifier
                Expect.equal challenge expected "S256 challenge should match RFC 7636 test vector"
            }

        testCaseAsync "code challenge output is base64url-encoded" <|
            async {
                let verifier = Crypto.CodeVerifier.generate cry
                let! challenge = Crypto.CodeChallenge.compute cry verifier
                Expect.isFalse (challenge.Contains("=")) "no padding"
                Expect.isFalse (challenge.Contains("+")) "no +"
                Expect.isFalse (challenge.Contains("/")) "no /"
            }
    ]

    testList "DotNet.crypto RSA" [
        testCaseAsync "importRsaKey and rsaVerify roundtrip" <|
            async {
                let rsa, jwksKey = Tests.Helpers.generateTestKeyPair ()
                let data = System.Text.Encoding.UTF8.GetBytes "test data to sign"
                let signature = rsa.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1)
                let! key = cry.importRsaKey jwksKey
                let! valid = cry.rsaVerify "RS256" key signature data
                Expect.isTrue valid "signature should verify"
            }

        testCaseAsync "rsaVerify rejects tampered data" <|
            async {
                let rsa, jwksKey = Tests.Helpers.generateTestKeyPair ()
                let data = System.Text.Encoding.UTF8.GetBytes "original data"
                let signature = rsa.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1)
                let! key = cry.importRsaKey jwksKey
                let tamperedData = System.Text.Encoding.UTF8.GetBytes "tampered data"
                let! valid = cry.rsaVerify "RS256" key signature tamperedData
                Expect.isFalse valid "tampered data should not verify"
            }
    ]

    testList "Utf8" [
        testCase "utf8 roundtrip" <| fun _ ->
            let text = "Hello, World! \u00E9\u00FC\u00F1"
            let bytes = Crypto.Utf8.encode text
            let decoded = Crypto.Utf8.decode bytes
            Expect.equal decoded text "UTF-8 roundtrip should preserve text"

        testCase "utf8 matches .NET UTF-8 for multi-byte text" <| fun _ ->
            let text = "Hello, \u00E9\u00FC\u00F1 \u4E2D\u6587 \U0001F600"
            let bytes = Crypto.Utf8.encode text
            let expected = System.Text.Encoding.UTF8.GetBytes text
            Expect.equal bytes expected "Crypto.Utf8.encode should match System.Text.Encoding.UTF8"
            let decoded = Crypto.Utf8.decode bytes
            Expect.equal decoded text "Crypto.Utf8.decode should preserve text"
    ]
]
