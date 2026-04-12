module internal Elmish.OIDC.ReactNativeInterop

open Fable.Core
open Fable.Core.JsInterop

module Crypto =

    [<Emit("globalThis.crypto.getRandomValues($0)")>]
    let getRandomValues (_buf: byte[]) : byte[] = jsNative

    [<Emit("globalThis.crypto.subtle.importKey('jwk', {kty: $0.kty, n: $0.n, e: $0.e, alg: $0.alg, ext: true}, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['verify'])")>]
    let importJwk (_key: obj) : JS.Promise<obj> = jsNative

    [<Emit("globalThis.crypto.subtle.verify('RSASSA-PKCS1-v1_5', $0, $1, $2)")>]
    let verify (_key: obj) (_signature: JS.ArrayBuffer) (_data: JS.ArrayBuffer) : JS.Promise<bool> = jsNative

module Encoding =

    [<Emit("new TextEncoder().encode($0).buffer")>]
    let toArrayBuffer (_s: string) : JS.ArrayBuffer = jsNative

    [<Emit("new TextDecoder().decode($0)")>]
    let fromBytes (_bytes: byte[]) : string = jsNative

    [<Emit("btoa(String.fromCharCode.apply(null, $0))")>]
    let btoaFromBytes (_bytes: byte[]) : string = jsNative

    [<Emit("Uint8Array.from(atob($0), function(c) { return c.charCodeAt(0); })")>]
    let atobToBytes (_s: string) : byte[] = jsNative

module Buffers =

    [<Emit("new Uint8Array($0)")>]
    let toBytes (_buf: JS.ArrayBuffer) : byte[] = jsNative

    [<Emit("$0.buffer")>]
    let toArrayBuffer (_bytes: byte[]) : JS.ArrayBuffer = jsNative

module Http =

    type Response =
        abstract text: unit -> JS.Promise<string>

    [<Emit("fetch($0)")>]
    let get (_url: string) : JS.Promise<Response> = jsNative

    [<Emit("fetch($0, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: $1 })")>]
    let postForm (_url: string) (_body: string) : JS.Promise<Response> = jsNative

module UrlSearchParams =

    [<Emit("new URLSearchParams($0)")>]
    let create (_query: string) : obj = jsNative

    [<Emit("$1.get($0)")>]
    let private get (_key: string) (_ps: obj) : string = jsNative

    let tryGet (key: string) (ps: obj) : string option =
        let v = get key ps
        if isNull v then None else Some v

module Linking =

    [<Emit("encodeURIComponent($0)")>]
    let encodeURIComponent (_s: string) : string = jsNative

module WebBrowser =

    type AuthSessionResult =
        abstract ``type``: string
        abstract url: string

    [<ImportMember("expo-web-browser")>]
    let openAuthSessionAsync (_url: string) (_redirectUrl: string) : JS.Promise<AuthSessionResult> = jsNative

    [<ImportMember("expo-web-browser")>]
    let openBrowserAsync (_url: string) : JS.Promise<obj> = jsNative
