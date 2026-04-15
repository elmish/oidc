module Tests.CryptoTests

open Expecto
open Elmish.OIDC
open Elmish.OIDC.Types

let private enc = DotNet.encoding
let private cry = DotNet.crypto

[<Tests>]
let tests = testList "Crypto" [

    testList "base64UrlEncode" [
        testCase "empty input produces empty string" <| fun _ ->
            let result = Crypto.Base64Url.encode enc [||]
            Expect.equal result "" "empty bytes should produce empty string"

        testCase "strips padding characters" <| fun _ ->
            let result1 = Crypto.Base64Url.encode enc [| 0uy |]
            let result2 = Crypto.Base64Url.encode enc [| 0uy; 1uy |]
            Expect.isFalse (result1.Contains("=")) "should not contain padding (1 byte)"
            Expect.isFalse (result2.Contains("=")) "should not contain padding (2 bytes)"

        testCase "replaces + with - and / with _" <| fun _ ->
            let result = Crypto.Base64Url.encode enc [| 0xFBuy; 0xFFuy; 0xFEuy |]
            Expect.isFalse (result.Contains("+")) "should not contain +"
            Expect.isFalse (result.Contains("/")) "should not contain /"

        testCase "known input produces expected output" <| fun _ ->
            let bytes = [| 72uy; 101uy; 108uy; 108uy; 111uy |]
            let result = Crypto.Base64Url.encode enc bytes
            Expect.equal result "SGVsbG8" "Hello bytes should encode to SGVsbG8"
    ]

    testList "base64UrlDecode" [
        testCase "roundtrip preserves data" <| fun _ ->
            let original = [| 0uy; 1uy; 2uy; 127uy; 128uy; 255uy |]
            let decoded = original |> Crypto.Base64Url.encode enc |> Crypto.Base64Url.decode enc
            Expect.equal decoded original "roundtrip should preserve all byte values"

        testCase "restores padding before decoding" <| fun _ ->
            let result = Crypto.Base64Url.decode enc "AA"
            Expect.equal result [| 0uy |] "should decode unpadded input"

        testCase "roundtrip with 32 random bytes" <| fun _ ->
            let original = Crypto.randomBytes cry 32
            let decoded = original |> Crypto.Base64Url.encode enc |> Crypto.Base64Url.decode enc
            Expect.equal decoded original "roundtrip should preserve 32 random bytes"
    ]

    testList "PKCE (RFC 7636)" [
        testCaseAsync "computeCodeChallenge matches RFC 7636 Appendix B test vector" <|
            async {
                let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                let! challenge = Crypto.CodeChallenge.compute cry enc verifier
                Expect.equal challenge expected "S256 challenge should match RFC 7636 test vector"
            }

        testCaseAsync "code challenge output is base64url-encoded" <|
            async {
                let verifier = Crypto.CodeVerifier.generate cry enc
                let! challenge = Crypto.CodeChallenge.compute cry enc verifier
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
                let! valid = cry.rsaVerify key signature data
                Expect.isTrue valid "signature should verify"
            }

        testCaseAsync "rsaVerify rejects tampered data" <|
            async {
                let rsa, jwksKey = Tests.Helpers.generateTestKeyPair ()
                let data = System.Text.Encoding.UTF8.GetBytes "original data"
                let signature = rsa.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1)
                let! key = cry.importRsaKey jwksKey
                let tamperedData = System.Text.Encoding.UTF8.GetBytes "tampered data"
                let! valid = cry.rsaVerify key signature tamperedData
                Expect.isFalse valid "tampered data should not verify"
            }
    ]

    testList "DotNet.encoding" [
        testCase "utf8 roundtrip" <| fun _ ->
            let text = "Hello, World! \u00E9\u00FC\u00F1"
            let bytes = enc.utf8Encode text
            let decoded = enc.utf8Decode bytes
            Expect.equal decoded text "UTF-8 roundtrip should preserve text"

        testCase "base64 roundtrip" <| fun _ ->
            let original = [| 0uy; 1uy; 127uy; 128uy; 255uy |]
            let encoded = enc.base64Encode original
            let decoded = enc.base64Decode encoded
            Expect.equal decoded original "base64 roundtrip should preserve bytes"
    ]
]
