[<RequireQualifiedAccess>]
module Elmish.OIDC.ReactNativeNavigation

open Elmish.OIDC.Types
open Fable.Core.JsInterop
open Fable.Core

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
