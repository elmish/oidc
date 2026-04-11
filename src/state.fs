[<AutoOpen>]
module Elmish.OIDC.State

open System
open Fable.Core
open Fable.Core.JsInterop
open Elmish

// --- JS interop helpers ---

[<Emit("encodeURIComponent($0)")>]
let private encodeUri (_s: string) : string = jsNative

[<Emit("new URLSearchParams($0)")>]
let private createUrlSearchParams (_search: string) : obj = jsNative

// --- Mutable refs for two-phase initialization ---
// The Msg type cannot carry the discovery doc between DiscoveryLoaded and JwksLoaded,
// nor the nonce between callback processing and TokenReceived. These refs bridge the gap.
let mutable private pendingDiscovery : DiscoveryDocument option = None
let mutable private pendingNonce : string option = None

// --- Helpers ---

let private nowEpoch () : int64 =
    DateTimeOffset.UtcNow.ToUnixTimeSeconds()

let private buildAuthorizeUrl (doc: DiscoveryDocument) (opts: Options) (state: string) (nonce: string) (codeChallenge: string) : string =
    let scopes = opts.scopes |> String.concat " "
    doc.authorizationEndpoint
    + "?response_type=" + encodeUri "code"
    + "&client_id=" + encodeUri opts.clientId
    + "&scope=" + encodeUri scopes
    + "&redirect_uri=" + encodeUri opts.redirectUri
    + "&state=" + encodeUri state
    + "&nonce=" + encodeUri nonce
    + "&code_challenge=" + encodeUri codeChallenge
    + "&code_challenge_method=" + encodeUri "S256"

let private parseCallback () : (string * string) option =
    let search : string = Browser.Dom.window?location?search
    if isNullOrUndefined search || search.Length <= 1 then
        None
    else
        let ps = createUrlSearchParams search
        let code : string = ps?get("code")
        let state : string = ps?get("state")
        if isNullOrUndefined code || isNullOrUndefined state then
            None
        else
            Some (code, state)

let private stripCallbackFromUrl () : unit =
    let pathname : string = Browser.Dom.window?location?pathname
    Browser.Dom.window?history?replaceState(null, "", pathname)

let private buildSession (response: TokenResponse) (payload: JwtPayload) : Session<'info> =
    { accessToken = response.accessToken
      idToken = response.idToken
      tokenType = response.tokenType
      expiresAt = DateTimeOffset.FromUnixTimeSeconds(nowEpoch () + int64 response.expiresIn)
      scope = response.scope
      claims = payload
      userInfo = None }

let private startLoginCmd (doc: DiscoveryDocument) (opts: Options) (storage: IStorage) : Cmd<Msg<'info>> =
    Cmd.OfPromise.attempt
        (fun () ->
            let state = generateState ()
            let nonce = generateNonce ()
            let verifier = generateCodeVerifier ()
            computeCodeChallenge verifier
            |> Promise.map (fun challenge ->
                let authState =
                    { state = state
                      nonce = nonce
                      codeVerifier = verifier
                      redirectUri = opts.redirectUri }
                saveAuthState storage authState
                let url = buildAuthorizeUrl doc opts state nonce challenge
                Browser.Dom.window?location?href <- url))
        ()
        (fun ex -> ValidationFailed (NetworkError ex))

let private logoutCmd (doc: DiscoveryDocument) (opts: Options) (idTokenHint: string option) : Cmd<Msg<'info>> =
    match doc.endSessionEndpoint, opts.postLogoutRedirectUri with
    | Some endpoint, Some postLogoutUri ->
        Cmd.OfFunc.attempt
            (fun () ->
                let url =
                    endpoint + "?"
                    + (match idTokenHint with
                       | Some token -> "id_token_hint=" + encodeUri token + "&"
                       | None -> "")
                    + "post_logout_redirect_uri=" + encodeUri postLogoutUri
                Browser.Dom.window?location?href <- url)
            ()
            (fun _ -> LoggedOut)
    | _ ->
        Cmd.ofMsg LoggedOut

// --- Init ---

let init (opts: Options) (_storage: IStorage) : Model<'info> * Cmd<Msg<'info>> =
    ensureSubtleCrypto ()
    Initializing, Cmd.OfPromise.either fetchDiscovery opts.authority DiscoveryLoaded DiscoveryFailed

// --- Update ---

let update (opts: Options) (storage: IStorage) (getUserInfo: string -> string -> JS.Promise<'info>) (msg: Msg<'info>) (model: Model<'info>) : Model<'info> * Cmd<Msg<'info>> =
    match model, msg with
    // --- Initialization: fetch discovery then JWKS ---
    | Initializing, DiscoveryLoaded doc ->
        pendingDiscovery <- Some doc
        Initializing, Cmd.OfPromise.either fetchJwks doc.jwksUri JwksLoaded JwksFailed

    | Initializing, JwksLoaded jwks ->
        match pendingDiscovery with
        | Some doc ->
            pendingDiscovery <- None
            match parseCallback () with
            | Some (code, callbackState) ->
                stripCallbackFromUrl ()
                match loadAuthState storage with
                | Some authState when authState.state = callbackState ->
                    pendingNonce <- Some authState.nonce
                    Ready (doc, jwks, ExchangingCode),
                    Cmd.OfPromise.either
                        (fun () -> exchangeCode doc opts.clientId code authState.codeVerifier authState.redirectUri)
                        ()
                        TokenReceived
                        (fun ex -> ValidationFailed (TokenExchangeFailed ex.Message))
                | _ ->
                    Ready (doc, jwks, Unauthenticated), Cmd.none
            | None ->
                match loadSession storage with
                | Some response ->
                    Ready (doc, jwks, ValidatingToken),
                    Cmd.OfPromise.either
                        (fun () -> revalidateStoredToken opts (nowEpoch ()) response.idToken jwks)
                        ()
                        (fun result ->
                            match result with
                            | Ok payload -> TokenValidated (payload, response)
                            | Error err -> ValidationFailed (InvalidToken err))
                        (fun ex -> ValidationFailed (NetworkError ex))
                | None ->
                    Ready (doc, jwks, Unauthenticated), Cmd.none
        | None ->
            Failed (DiscoveryError (exn "Discovery document not available")), Cmd.none

    // --- Token exchange complete ---
    | Ready (doc, jwks, ExchangingCode), TokenReceived response ->
        match pendingNonce with
        | Some nonce ->
            pendingNonce <- None
            Ready (doc, jwks, ValidatingToken),
            Cmd.OfPromise.either
                (fun () -> validateIdToken opts nonce (nowEpoch ()) response.idToken jwks)
                ()
                (fun result ->
                    match result with
                    | Ok payload -> TokenValidated (payload, response)
                    | Error err -> ValidationFailed (InvalidToken err))
                (fun ex -> ValidationFailed (NetworkError ex))
        | None ->
            Ready (doc, jwks, Unauthenticated), Cmd.none

    // --- Token validated ---
    | Ready (doc, jwks, ValidatingToken), TokenValidated (payload, response) ->
        let session = buildSession response payload
        Ready (doc, jwks, Authenticated session),
        Cmd.batch [
            Cmd.OfFunc.attempt (saveSession storage) response (fun _ -> NoSession)
            Cmd.OfPromise.either
                (fun () -> getUserInfo doc.userinfoEndpoint session.accessToken)
                ()
                UserInfo
                UserInfoFailed
        ]

    // --- Validation / exchange failure in any ready sub-state ---
    | Ready (doc, jwks, _), ValidationFailed _ ->
        clearAll storage
        Ready (doc, jwks, Unauthenticated), Cmd.none

    // --- User info ---
    | Ready (doc, jwks, Authenticated session), UserInfo info ->
        Ready (doc, jwks, Authenticated { session with userInfo = Some info }), Cmd.none

    | Ready (doc, jwks, Authenticated session), UserInfoFailed _ ->
        Ready (doc, jwks, Authenticated session), Cmd.none

    // --- Token renewal timer ---
    | Ready (doc, jwks, Authenticated session), Tick ->
        let expiresInSeconds = int (session.expiresAt.ToUnixTimeSeconds() - nowEpoch ())
        if expiresInSeconds <= opts.renewBeforeExpirySeconds then
            Ready (doc, jwks, Renewing session),
            Cmd.OfPromise.either
                (fun () -> silentRenew doc opts jwks storage)
                ()
                SilentRenewResult
                (fun ex -> SilentRenewResult (Error (NetworkError ex)))
        else
            Ready (doc, jwks, Authenticated session), Cmd.none

    | Ready (_, _, Renewing _), Tick ->
        model, Cmd.none

    // --- Silent renewal results (Task 10 placeholder) ---
    | Ready (doc, jwks, Renewing session), SilentRenewResult (Ok (payload, response)) ->
        let newSession = buildSession response payload
        Ready (doc, jwks, Authenticated { newSession with userInfo = session.userInfo }),
        Cmd.OfFunc.attempt (saveSession storage) response (fun _ -> NoSession)

    | Ready (doc, jwks, Renewing session), SilentRenewResult (Error _) ->
        Ready (doc, jwks, Authenticated session), Cmd.none

    // --- Login ---
    | Ready (doc, jwks, _), LogIn ->
        Ready (doc, jwks, Redirecting), startLoginCmd doc opts storage

    // --- Logout ---
    | Ready (doc, jwks, readyState), LogOut ->
        clearAll storage
        let idTokenHint =
            match readyState with
            | Authenticated session -> Some session.idToken
            | Renewing session -> Some session.idToken
            | _ -> None
        Ready (doc, jwks, Unauthenticated), logoutCmd doc opts idTokenHint

    | Ready (doc, jwks, _), LoggedOut ->
        Ready (doc, jwks, Unauthenticated), Cmd.none

    // --- Fatal errors ---
    | _, DiscoveryFailed ex ->
        Failed (DiscoveryError ex), Cmd.none

    | _, JwksFailed ex ->
        Failed (DiscoveryError ex), Cmd.none

    // --- Catch-all: ignore unexpected messages ---
    | _ ->
        model, Cmd.none
