[<AutoOpen>]
module Elmish.OIDC.Renewal

open System
open Fable.Core
open Fable.Core.JsInterop

let private nowEpoch () : int64 =
    DateTimeOffset.UtcNow.ToUnixTimeSeconds()

let private buildSilentAuthorizeUrl (doc: DiscoveryDocument) (opts: Options) (state: string) (nonce: string) (codeChallenge: string) : string =
    let encode = Browser.Dom.window.encodeURIComponent
    let scopes = opts.scopes |> String.concat " "
    let redirectUri =
        match opts.silentRedirectUri with
        | Some uri -> uri
        | None -> opts.redirectUri
    doc.authorizationEndpoint
    + "?response_type=" + encode "code"
    + "&client_id=" + encode opts.clientId
    + "&scope=" + encode scopes
    + "&redirect_uri=" + encode redirectUri
    + "&state=" + encode state
    + "&nonce=" + encode nonce
    + "&code_challenge=" + encode codeChallenge
    + "&code_challenge_method=" + encode "S256"
    + "&prompt=" + encode "none"

let silentRenew (doc: DiscoveryDocument) (opts: Options) (jwks: Jwks) (storage: IStorage) : JS.Promise<Result<JwtPayload * TokenResponse, OidcError>> =
    match opts.silentRedirectUri with
    | None ->
        Promise.lift (Error (InvalidToken "silentRedirectUri is not configured"))
    | Some silentUri ->
        let state = generateState ()
        let nonce = generateNonce ()
        let verifier = generateCodeVerifier ()

        computeCodeChallenge verifier
        |> Promise.bind (fun challenge ->
            let authState =
                { state = state
                  nonce = nonce
                  codeVerifier = verifier
                  redirectUri = silentUri }
            saveAuthState storage authState

            let url = buildSilentAuthorizeUrl doc opts state nonce challenge
            let window = Browser.Dom.window
            let document = Browser.Dom.document

            JS.Constructors.Promise.Create(fun resolve _reject ->
                let mutable timerId = 0.
                let mutable listener : (Browser.Types.Event -> unit) option = None

                let iframe = document.createElement "iframe" :?> Browser.Types.HTMLIFrameElement
                emitJsExpr iframe "$0.style.display = 'none'"
                iframe.src <- url
                document.body.appendChild iframe |> ignore

                let cleanup () =
                    window.clearTimeout timerId
                    listener |> Option.iter (fun h -> window.removeEventListener("message", h))
                    listener <- None
                    try document.body.removeChild iframe |> ignore
                    with _ -> ()

                let onMessage (event: Browser.Types.Event) =
                    let msgEvent = event :?> Browser.Types.MessageEvent
                    if msgEvent.origin = window.location.origin then
                        let data = msgEvent.data |> string
                        if not (isNull data) && data.StartsWith("?") then
                            let ps = Interop.UrlSearchParams.create data

                            cleanup ()

                            match Interop.UrlSearchParams.tryGet "error" ps with
                            | Some error ->
                                let desc = Interop.UrlSearchParams.tryGet "error_description" ps |> Option.defaultValue ""
                                resolve (Error (ServerError (error, desc)))
                            | None ->
                                match Interop.UrlSearchParams.tryGet "code" ps, Interop.UrlSearchParams.tryGet "state" ps with
                                | Some code, Some returnedState when returnedState = state ->
                                    exchangeCode doc opts.clientId code verifier silentUri
                                    |> Promise.bind (fun response ->
                                        validateIdToken opts nonce (nowEpoch ()) response.idToken jwks
                                        |> Promise.map (fun result ->
                                            match result with
                                            | Ok payload -> Ok (payload, response)
                                            | Error err -> Error (InvalidToken err)))
                                    |> Promise.catch (fun ex ->
                                        Error (TokenExchangeFailed ex.Message))
                                    |> Promise.map resolve
                                    |> ignore
                                | Some _, Some _ ->
                                    resolve (Error InvalidState)
                                | _ ->
                                    resolve (Error (InvalidToken "Silent renew response missing code or state"))

                listener <- Some onMessage
                window.addEventListener("message", onMessage)

                timerId <- window.setTimeout((fun () ->
                    cleanup ()
                    resolve (Error (NetworkError (exn "Silent renewal timed out after 10 seconds")))
                ), 10000)))

let tokenExpirySubscription (dispatch: Msg<'info> -> unit) : IDisposable =
    let id = Browser.Dom.window.setInterval((fun () -> dispatch Tick), 30000)
    { new IDisposable with
        member _.Dispose() = Browser.Dom.window.clearInterval id }
