[<AutoOpen>]
module Elmish.OIDC.Crypto

open Fable.Core

let base64UrlEncode (bytes: byte[]) : string =
    Interop.Encoding.btoaFromBytes bytes
    |> fun s -> s.Replace('+', '-').Replace('/', '_').TrimEnd('=')

let base64UrlDecode (s: string) : byte[] =
    let padded =
        let r = s.Length % 4
        if r = 0 then s
        else s + System.String('=', 4 - r)
    padded.Replace('-', '+').Replace('_', '/')
    |> Interop.Encoding.atobToBytes

let randomBytes (len: int) : byte[] =
    let buf = Array.zeroCreate<byte> len
    Interop.Crypto.getRandomValues buf |> ignore
    buf

let generateState () : string =
    randomBytes 32 |> base64UrlEncode

let generateNonce () : string =
    randomBytes 32 |> base64UrlEncode

let generateCodeVerifier () : string =
    randomBytes 32 |> base64UrlEncode

let computeCodeChallenge (verifier: string) : JS.Promise<string> =
    Interop.Crypto.sha256Digest verifier
    |> Promise.map (fun buf -> Interop.Buffers.toBytes buf |> base64UrlEncode)

let ensureSubtleCrypto () =
    if not (Interop.Crypto.isAvailable ()) then
        failwith "OIDC requires a secure context (HTTPS or localhost) for Web Crypto API"
