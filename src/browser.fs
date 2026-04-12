[<RequireQualifiedAccess>]
module Elmish.OIDC.Browser

open System
open Elmish.OIDC.Types
open Fable.Core
open Fable.Core.JsInterop

let crypto =
    { new CryptoProvider with
        member _.randomBytes len =
            let buf = Array.zeroCreate<byte> len
            Interop.Crypto.getRandomValues buf |> ignore
            buf

        member _.sha256 (data: byte[]) =
            async {
                let ab = Interop.Buffers.toArrayBuffer data
                let! result =
                    emitJsExpr ab "crypto.subtle.digest('SHA-256', $0)"
                    |> Async.AwaitPromise
                return Interop.Buffers.toBytes result
            }

        member _.importRsaKey (key: JwksKey) =
            Interop.Crypto.importJwk (key :> obj) |> Async.AwaitPromise

        member _.rsaVerify (key: obj) (signature: byte[]) (data: byte[]) =
            Interop.Crypto.verify key (Interop.Buffers.toArrayBuffer signature) (Interop.Buffers.toArrayBuffer data)
            |> Async.AwaitPromise }

let encoding =
    { new EncodingProvider with
        member _.utf8Encode (s: string) =
            let ab : JS.ArrayBuffer = Interop.Encoding.toArrayBuffer s
            Interop.Buffers.toBytes ab

        member _.utf8Decode (bytes: byte[]) =
            Interop.Encoding.fromBytes bytes

        member _.base64Encode (bytes: byte[]) =
            Interop.Encoding.btoaFromBytes bytes

        member _.base64Decode (s: string) =
            Interop.Encoding.atobToBytes s }

let http =
    { new HttpClient with
        member _.getText (url: string) =
            async {
                let! response = Interop.Http.get url |> Async.AwaitPromise
                return! response.text () |> Async.AwaitPromise
            }

        member _.postForm (url: string) (body: string) =
            async {
                let! response = Interop.Http.postForm url body |> Async.AwaitPromise
                return! response.text () |> Async.AwaitPromise
            } }

let navigation =
    { new Navigation with
        member _.redirect (url: string) =
            Browser.Dom.window.location.href <- url

        member _.getCallbackParams () =
            let search = Browser.Dom.window.location.search
            if isNull search || search.Length <= 1 then
                None
            else
                let ps = Interop.UrlSearchParams.create search
                match Interop.UrlSearchParams.tryGet "code" ps, Interop.UrlSearchParams.tryGet "state" ps with
                | Some code, Some state -> Some (code, state)
                | _ -> None

        member _.clearCallbackParams () =
            Browser.Dom.window.history.replaceState(null, "", Browser.Dom.window.location.pathname)

        member _.encodeURIComponent (s: string) =
            Browser.Dom.window.encodeURIComponent s }

let timer =
    { new TimerProvider with
        member _.createInterval (callback: unit -> unit) (ms: int) =
            let id = Browser.Dom.window.setInterval(callback, ms)
            { new IDisposable with
                member _.Dispose() = Browser.Dom.window.clearInterval id }

        member _.createTimeout (callback: unit -> unit) (ms: int) =
            let id = Browser.Dom.window.setTimeout(callback, ms)
            { new IDisposable with
                member _.Dispose() = Browser.Dom.window.clearTimeout id } }

let private makeStorage (storage: Browser.Types.Storage) =
    { new Storage with
        member _.getItem key =
            storage.[key] |> Option.ofObj
        member _.setItem key value =
            storage.[key] <- value
        member _.removeItem key =
            storage.removeItem key }

let sessionStorage = makeStorage Browser.Dom.window.sessionStorage

let localStorage = makeStorage Browser.Dom.window.localStorage

let ensureCrypto () =
    if not (Interop.Crypto.isAvailable ()) then
        failwith "OIDC requires a secure context (HTTPS or localhost) for Web Crypto API"
