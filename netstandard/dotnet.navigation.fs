[<RequireQualifiedAccess>]
module Elmish.OIDC.DotNetNavigation

open System
open System.Diagnostics
open System.Net
open Elmish.OIDC.Types

type private LoopbackState =
    { mutable callbackParams: (string * string) option }

/// Creates a Navigation that uses RFC 8252 loopback redirect.
/// `redirect` opens the system browser and starts an HttpListener on localhost to capture the callback.
let loopback (port: int) =
    let state = { callbackParams = None }
    let redirectUri = $"http://127.0.0.1:{port}/"

    { new Navigation with
        member _.redirect (url: string) =
            // Start listener before opening browser
            let listener = new HttpListener()
            listener.Prefixes.Add(redirectUri)
            listener.Start()

            // Open system browser
            Process.Start(ProcessStartInfo(url, UseShellExecute = true)) |> ignore

            // Wait synchronously for the callback (runs on Elmish async dispatch)
            let context = listener.GetContext()
            let query = context.Request.QueryString
            let code = query.["code"]
            let callbackState = query.["state"]

            // Send response to browser
            let response = context.Response
            let body = Text.Encoding.UTF8.GetBytes("<html><body>Authentication complete. You can close this window.</body></html>")
            response.ContentType <- "text/html"
            response.ContentLength64 <- int64 body.Length
            response.OutputStream.Write(body, 0, body.Length)
            response.Close()
            listener.Stop()

            if not (isNull code) && not (isNull callbackState) then
                state.callbackParams <- Some (code, callbackState)

        member _.getCallbackParams () =
            state.callbackParams

        member _.clearCallbackParams () =
            state.callbackParams <- None

        member _.encodeURIComponent (s: string) =
            Uri.EscapeDataString s }

/// Creates a Navigation that uses a custom URI scheme callback.
/// The app must register the scheme with the OS and call `setCallbackParams` when it receives the callback.
let customScheme () =
    let state = { callbackParams = None }

    let nav =
        { new Navigation with
            member _.redirect (url: string) =
                Process.Start(ProcessStartInfo(url, UseShellExecute = true)) |> ignore

            member _.getCallbackParams () =
                state.callbackParams

            member _.clearCallbackParams () =
                state.callbackParams <- None

            member _.encodeURIComponent (s: string) =
                Uri.EscapeDataString s }

    // Return nav + setter for the callback params
    nav, (fun code callbackState -> state.callbackParams <- Some (code, callbackState))
