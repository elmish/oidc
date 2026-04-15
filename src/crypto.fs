[<RequireQualifiedAccess>]
module Elmish.OIDC.Crypto

open Elmish.OIDC.Types

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
