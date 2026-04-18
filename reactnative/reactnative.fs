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
                // RN path does not pre-import: the JWK is consumed directly at verify time
                // via rnqc.createPublicKey({format:'jwk'}). See ReactNativeInterop.Crypto.verify.
                async { return key :> obj }

            member _.rsaVerify (alg: string) (key: obj) (signature: byte[]) (data: byte[]) =
                let rsaAlg = Elmish.OIDC.Crypto.rsaAlgorithm alg
                let saltLength = if rsaAlg.name = "RSA-PSS" then (match rsaAlg.hash with "SHA-256" -> 32 | "SHA-384" -> 48 | _ -> 64) else 0
                ReactNativeInterop.Crypto.verify key signature data rsaAlg.hash saltLength rsaAlg.name
                |> Async.AwaitPromise }

    let http =
        { new HttpClient with
            member _.getText (url: string) =
                async {
                    let! response = ReactNativeInterop.Http.get url |> Async.AwaitPromise
                    if not response.ok then
                        return failwith $"HTTP {response.status} {response.statusText} from GET {url}"
                    return! response.text () |> Async.AwaitPromise
                }

            member _.postForm (url: string) (body: string) =
                async {
                    let! response = ReactNativeInterop.Http.postForm url body |> Async.AwaitPromise
                    let! text = response.text () |> Async.AwaitPromise
                    if not response.ok then
                        JS.console.log("postForm error response body:", text)
                        return failwith $"HTTP {response.status} {response.statusText} from POST {url}"
                    return text
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
                        async {
                            ReactNativeInterop.WebBrowser.openBrowserAsync url |> ignore
                            return None
                        }

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

            let nav =
                { new Navigation with
                    member _.redirect (url: string) =
                        async {
                            JS.console.log("authSession.redirect called, url:", url)
                            JS.console.log("authSession.redirect redirectUri:", redirectUri)
                            let! result =
                                ReactNativeInterop.WebBrowser.openAuthSessionAsync url redirectUri
                                |> Async.AwaitPromise
                            JS.console.log("openAuthSessionAsync result:", result)
                            if result.``type`` = "success" && not (isNull result.url) then
                                let urlStr = result.url
                                match urlStr.IndexOf '?' with
                                | -1 -> return None
                                | idx ->
                                    let query = urlStr.Substring idx
                                    let ps = ReactNativeInterop.UrlSearchParams.create query
                                    match ReactNativeInterop.UrlSearchParams.tryGet "code" ps,
                                          ReactNativeInterop.UrlSearchParams.tryGet "state" ps with
                                    | Some code, Some callbackState ->
                                        return Some (code, callbackState)
                                    | _ -> return None
                            else
                                return None
                        }

                    member _.getCallbackParams () =
                        None

                    member _.clearCallbackParams () =
                        ()

                    member _.encodeURIComponent (s: string) =
                        ReactNativeInterop.Linking.encodeURIComponent s }

            nav

    let ensureCrypto () =
        if not (ReactNativeInterop.Crypto.isAvailable ()) then
            failwith "Elmish.OIDC requires the Web Crypto API (globalThis.crypto.subtle), which is not available in the default React Native runtime. Install react-native-quick-crypto and register its polyfill at your app entry point (before importing this library)."
