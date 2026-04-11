[<AutoOpen>]
module Elmish.OIDC.Renewal

open System
open Fable.Core
open Fable.Core.JsInterop

// --- JS interop ---

[<Emit("encodeURIComponent($0)")>]
let private encodeUri (_s: string) : string = jsNative

[<Emit("document.createElement('iframe')")>]
let private createIframe () : obj = jsNative

[<Emit("window.addEventListener('message', $0)")>]
let private addMessageListener (_handler: obj -> unit) : unit = jsNative

[<Emit("window.removeEventListener('message', $0)")>]
let private removeMessageListener (_handler: obj -> unit) : unit = jsNative

[<Emit("setTimeout($0, $1)")>]
let private setTimeout (_fn: unit -> unit) (_ms: int) : int = jsNative

[<Emit("clearTimeout($0)")>]
let private clearTimeout (_id: int) : unit = jsNative

[<Emit("setInterval($0, $1)")>]
let private setInterval (_fn: unit -> unit) (_ms: int) : int = jsNative

[<Emit("clearInterval($0)")>]
let private clearInterval (_id: int) : unit = jsNative

[<Emit("new URLSearchParams($0)")>]
let private createUrlSearchParams (_search: string) : obj = jsNative

// --- Helpers ---

let private nowEpoch () : int64 =
    DateTimeOffset.UtcNow.ToUnixTimeSeconds()

let private buildSilentAuthorizeUrl (doc: DiscoveryDocument) (opts: Options) (state: string) (nonce: string) (codeChallenge: string) : string =
    let scopes = opts.scopes |> String.concat " "
    let redirectUri =
        match opts.silentRedirectUri with
        | Some uri -> uri
        | None -> opts.redirectUri
    doc.authorizationEndpoint
    + "?response_type=" + encodeUri "code"
    + "&client_id=" + encodeUri opts.clientId
    + "&scope=" + encodeUri scopes
    + "&redirect_uri=" + encodeUri redirectUri
    + "&state=" + encodeUri state
    + "&nonce=" + encodeUri nonce
    + "&code_challenge=" + encodeUri codeChallenge
    + "&code_challenge_method=" + encodeUri "S256"
    + "&prompt=" + encodeUri "none"

// --- Silent renewal via hidden iframe ---

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

            JS.Constructors.Promise.Create(fun resolve _reject ->
                let mutable timerId = 0
                let mutable handler : (obj -> unit) option = None
                let iframe = createIframe ()
                iframe?style?display <- "none"
                iframe?src <- url
                Browser.Dom.window?document?body?appendChild(iframe) |> ignore

                let cleanup () =
                    clearTimeout timerId
                    handler |> Option.iter removeMessageListener
                    handler <- None
                    try Browser.Dom.window?document?body?removeChild(iframe) |> ignore
                    with _ -> ()

                let onMessage (event: obj) =
                    let origin : string = event?origin
                    let expectedOrigin : string = Browser.Dom.window?location?origin
                    if origin = expectedOrigin then
                        let data : string = event?data
                        if not (isNullOrUndefined data) && data.StartsWith("?") then
                            let ps = createUrlSearchParams data
                            let code : string = ps?get("code")
                            let returnedState : string = ps?get("state")
                            let error : string = ps?get("error")

                            cleanup ()

                            if not (isNullOrUndefined error) then
                                let desc : string = ps?get("error_description")
                                let description = if isNullOrUndefined desc then "" else desc
                                resolve (Error (ServerError (error, description)))
                            elif isNullOrUndefined code || isNullOrUndefined returnedState then
                                resolve (Error (InvalidToken "Silent renew response missing code or state"))
                            elif returnedState <> state then
                                resolve (Error InvalidState)
                            else
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

                handler <- Some onMessage
                addMessageListener onMessage

                timerId <- setTimeout (fun () ->
                    cleanup ()
                    resolve (Error (NetworkError (exn "Silent renewal timed out after 10 seconds")))
                ) 10000))

// --- Elmish subscription for token expiry timer ---

let tokenExpirySubscription (dispatch: Msg<'info> -> unit) : IDisposable =
    let id = setInterval (fun () -> dispatch Tick) 30000
    { new IDisposable with
        member _.Dispose() = clearInterval id }
