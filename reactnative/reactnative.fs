namespace Elmish.OIDC

open System
open Elmish.OIDC.Types
open Fable.Core
open Fable.Core.JsInterop

[<RequireQualifiedAccess>]
module ReactNative =

    let crypto =
        { new CryptoProvider with
            member _.randomBytes len =
                let buf = Array.zeroCreate<byte> len
                ReactNativeInterop.Crypto.getRandomValues buf |> ignore
                buf

            member _.sha256 (data: byte[]) =
                async {
                    let ab = ReactNativeInterop.Buffers.toArrayBuffer data
                    let! result =
                        emitJsExpr ab "globalThis.crypto.subtle.digest('SHA-256', $0)"
                        |> Async.AwaitPromise
                    return ReactNativeInterop.Buffers.toBytes result
                }

            member _.importRsaKey (key: JwksKey) =
                ReactNativeInterop.Crypto.importJwk (key :> obj) |> Async.AwaitPromise

            member _.rsaVerify (key: obj) (signature: byte[]) (data: byte[]) =
                ReactNativeInterop.Crypto.verify key (ReactNativeInterop.Buffers.toArrayBuffer signature) (ReactNativeInterop.Buffers.toArrayBuffer data)
                |> Async.AwaitPromise }

    let encoding =
        { new EncodingProvider with
            member _.utf8Encode (s: string) =
                let ab : JS.ArrayBuffer = ReactNativeInterop.Encoding.toArrayBuffer s
                ReactNativeInterop.Buffers.toBytes ab

            member _.utf8Decode (bytes: byte[]) =
                ReactNativeInterop.Encoding.fromBytes bytes

            member _.base64Encode (bytes: byte[]) =
                ReactNativeInterop.Encoding.btoaFromBytes bytes

            member _.base64Decode (s: string) =
                ReactNativeInterop.Encoding.atobToBytes s }

    let http =
        { new HttpClient with
            member _.getText (url: string) =
                async {
                    let! response = ReactNativeInterop.Http.get url |> Async.AwaitPromise
                    return! response.text () |> Async.AwaitPromise
                }

            member _.postForm (url: string) (body: string) =
                async {
                    let! response = ReactNativeInterop.Http.postForm url body |> Async.AwaitPromise
                    return! response.text () |> Async.AwaitPromise
                } }

    let timer =
        { new TimerProvider with
            member _.createInterval (callback: unit -> unit) (ms: int) =
                let id : float = JsInterop.emitJsExpr (callback, ms) "setInterval($0, $1)"
                { new IDisposable with
                    member _.Dispose() = JsInterop.emitJsExpr id "clearInterval($0)" }

            member _.createTimeout (callback: unit -> unit) (ms: int) =
                let id : float = JsInterop.emitJsExpr (callback, ms) "setTimeout($0, $1)"
                { new IDisposable with
                    member _.Dispose() = JsInterop.emitJsExpr id "clearTimeout($0)" } }

    type MemoryStorage() =
        let mutable store = Map.empty<string, string>
        interface Storage with
            member _.getItem key =
                store |> Map.tryFind key
            member _.setItem key value =
                store <- store |> Map.add key value
            member _.removeItem key =
                store <- store |> Map.remove key

    let memoryStorage () = MemoryStorage() :> Storage

    module Navigation =
        type private CallbackState =
            { mutable callbackParams: (string * string) option }

        /// Creates a Navigation that opens the system browser and expects the app
        /// to feed callback params via deep linking.
        /// Returns (Navigation, setCallbackParams) where setCallbackParams should be
        /// called from the app's deep link handler with (code, state).
        let deepLink () =
            let state = { callbackParams = None }

            let nav =
                { new Navigation with
                    member _.redirect (url: string) =
                        ReactNativeInterop.WebBrowser.openBrowserAsync url |> ignore

                    member _.getCallbackParams () =
                        state.callbackParams

                    member _.clearCallbackParams () =
                        state.callbackParams <- None

                    member _.encodeURIComponent (s: string) =
                        ReactNativeInterop.Linking.encodeURIComponent s }

            nav, (fun code callbackState -> state.callbackParams <- Some (code, callbackState))

        /// Creates a Navigation that uses expo-web-browser's openAuthSessionAsync.
        /// The auth session opens an in-app browser that automatically captures
        /// the redirect and returns code + state via the Promise result.
        let authSession (redirectUri: string) =
            let state = { callbackParams = None }

            let nav =
                { new Navigation with
                    member _.redirect (url: string) =
                        ReactNativeInterop.WebBrowser.openAuthSessionAsync url redirectUri
                        |> Promise.iter (fun (result: ReactNativeInterop.WebBrowser.AuthSessionResult) ->
                            if result.``type`` = "success" && not (isNull result.url) then
                                let urlStr = result.url
                                match urlStr.IndexOf '?' with
                                | -1 -> ()
                                | idx ->
                                    let query = urlStr.Substring idx
                                    let ps = ReactNativeInterop.UrlSearchParams.create query
                                    match ReactNativeInterop.UrlSearchParams.tryGet "code" ps,
                                          ReactNativeInterop.UrlSearchParams.tryGet "state" ps with
                                    | Some code, Some callbackState ->
                                        state.callbackParams <- Some (code, callbackState)
                                    | _ -> ())

                    member _.getCallbackParams () =
                        state.callbackParams

                    member _.clearCallbackParams () =
                        state.callbackParams <- None

                    member _.encodeURIComponent (s: string) =
                        ReactNativeInterop.Linking.encodeURIComponent s }

            nav
