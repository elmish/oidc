[<RequireQualifiedAccess>]
module Elmish.OIDC.Crypto

open Elmish.OIDC.Types

let base64UrlEncode (encoding: EncodingProvider) (bytes: byte[]) : string =
    encoding.base64Encode bytes
    |> fun s -> s.Replace('+', '-').Replace('/', '_').TrimEnd('=')

let base64UrlToBase64 (s: string) : string =
    let padded =
        let r = s.Length % 4
        if r = 0 then s
        else s + System.String('=', 4 - r)
    padded.Replace('-', '+').Replace('_', '/')

let base64UrlDecode (encoding: EncodingProvider) (s: string) : byte[] =
    base64UrlToBase64 s |> encoding.base64Decode

let randomBytes (crypto: CryptoProvider) (len: int) : byte[] =
    crypto.randomBytes len

let generateState (crypto: CryptoProvider) (encoding: EncodingProvider) : string =
    randomBytes crypto 32 |> base64UrlEncode encoding

let generateNonce (crypto: CryptoProvider) (encoding: EncodingProvider) : string =
    randomBytes crypto 32 |> base64UrlEncode encoding

let generateCodeVerifier (crypto: CryptoProvider) (encoding: EncodingProvider) : string =
    randomBytes crypto 32 |> base64UrlEncode encoding

let computeCodeChallenge (crypto: CryptoProvider) (encoding: EncodingProvider) (verifier: string) : Async<string> =
    async {
        let! hash = crypto.sha256 (encoding.utf8Encode verifier)
        return base64UrlEncode encoding hash
    }
