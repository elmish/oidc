[<AutoOpen>]
module Elmish.OIDC.Crypto

open Fable.Core
open Fable.Core.JsInterop

[<Emit("btoa(String.fromCharCode.apply(null, $0))")>]
let private btoaFromBytes (_bytes: byte[]) : string = jsNative

let base64UrlEncode (bytes: byte[]) : string =
    btoaFromBytes bytes
    |> fun s -> s.Replace('+', '-').Replace('/', '_').TrimEnd('=')

[<Emit("Uint8Array.from(atob($0), function(c) { return c.charCodeAt(0); })")>]
let private atobToBytes (_s: string) : byte[] = jsNative

let base64UrlDecode (s: string) : byte[] =
    let padded =
        let r = s.Length % 4
        if r = 0 then s
        else s + System.String('=', 4 - r)
    padded.Replace('-', '+').Replace('_', '/')
    |> atobToBytes

let randomBytes (len: int) : byte[] =
    let buf = Array.zeroCreate<byte> len
    Browser.Dom.window?crypto?getRandomValues(buf) |> ignore
    buf

let generateState () : string =
    randomBytes 32 |> base64UrlEncode

let generateNonce () : string =
    randomBytes 32 |> base64UrlEncode

let generateCodeVerifier () : string =
    randomBytes 32 |> base64UrlEncode

[<Emit("crypto.subtle.digest('SHA-256', new TextEncoder().encode($0))")>]
let private sha256Digest (_input: string) : JS.Promise<JS.ArrayBuffer> = jsNative

[<Emit("new Uint8Array($0)")>]
let private toByteArray (_buf: JS.ArrayBuffer) : byte[] = jsNative

let computeCodeChallenge (verifier: string) : JS.Promise<string> =
    sha256Digest verifier
    |> Promise.map (fun buf -> toByteArray buf |> base64UrlEncode)

let ensureSubtleCrypto () =
    if isNullOrUndefined (Browser.Dom.window?crypto) || isNullOrUndefined (Browser.Dom.window?crypto?subtle) then
        failwith "OIDC requires a secure context (HTTPS or localhost) for Web Crypto API"
