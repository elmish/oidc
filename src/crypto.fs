[<RequireQualifiedAccess>]
module Elmish.OIDC.Crypto

open Elmish.OIDC.Types

type RsaAlgorithm =
    { name: string
      hash: string }

let rsaAlgorithm (alg: string) : RsaAlgorithm =
    match alg with
    | "RS256" -> { name = "RSASSA-PKCS1-v1_5"; hash = "SHA-256" }
    | "RS384" -> { name = "RSASSA-PKCS1-v1_5"; hash = "SHA-384" }
    | "RS512" -> { name = "RSASSA-PKCS1-v1_5"; hash = "SHA-512" }
    | "PS256" -> { name = "RSA-PSS"; hash = "SHA-256" }
    | "PS384" -> { name = "RSA-PSS"; hash = "SHA-384" }
    | "PS512" -> { name = "RSA-PSS"; hash = "SHA-512" }
    | _ -> failwith $"Unsupported RSA algorithm: {alg}"

let randomBytes (crypto: CryptoProvider) (len: int) : byte[] =
    crypto.randomBytes len

module Base64Url =

    let toBase64 (s: string) : string =
        let padded =
            let r = s.Length % 4
            if r = 0 then s
            else s + System.String('=', 4 - r)
        padded.Replace('-', '+').Replace('_', '/')

    let encode (encoding: EncodingProvider) (bytes: byte[]) : string =
        encoding.base64Encode bytes
        |> fun s -> s.Replace('+', '-').Replace('/', '_').TrimEnd('=')

    let decode (encoding: EncodingProvider) (s: string) : byte[] =
        toBase64 s |> encoding.base64Decode

module OAuthState =

    let generate (crypto: CryptoProvider) (encoding: EncodingProvider) : string =
        randomBytes crypto 32 |> Base64Url.encode encoding

module Nonce =

    let generate (crypto: CryptoProvider) (encoding: EncodingProvider) : string =
        randomBytes crypto 32 |> Base64Url.encode encoding

module CodeVerifier =

    let generate (crypto: CryptoProvider) (encoding: EncodingProvider) : string =
        randomBytes crypto 32 |> Base64Url.encode encoding

module CodeChallenge =

    let compute (crypto: CryptoProvider) (encoding: EncodingProvider) (verifier: string) : Async<string> =
        async {
            let! hash = crypto.sha256 (encoding.utf8Encode verifier)
            return Base64Url.encode encoding hash
        }
