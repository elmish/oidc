[<RequireQualifiedAccess>]
module Elmish.OIDC.State

open Elmish.OIDC.Types
open System
open Elmish

let mutable private pendingDiscovery : DiscoveryDocument option = None
let mutable private pendingNonce : string option = None

let private nowEpoch () : int64 =
    DateTimeOffset.UtcNow.ToUnixTimeSeconds()

module AuthorizeUrl =

    let build (nav: Navigation) (doc: DiscoveryDocument) (opts: Options) (state: string) (nonce: string) (codeChallenge: string) : string =
        let encode = nav.encodeURIComponent
        let scopes = opts.scopes |> String.concat " "
        doc.authorizationEndpoint
        + "?response_type=" + encode "code"
        + "&client_id=" + encode opts.clientId
        + "&scope=" + encode scopes
        + "&redirect_uri=" + encode opts.redirectUri
        + "&state=" + encode state
        + "&nonce=" + encode nonce
        + "&code_challenge=" + encode codeChallenge
        + "&code_challenge_method=" + encode "S256"

module Login =

    let startCmd (platform: Platform) (doc: DiscoveryDocument) (opts: Options) : Cmd<Msg<'info>> =
        Cmd.OfAsync.either
            (fun () ->
                async {
                    let state = Crypto.OAuthState.generate platform.crypto platform.encoding
                    let nonce = Crypto.Nonce.generate platform.crypto platform.encoding
                    let verifier = Crypto.CodeVerifier.generate platform.crypto platform.encoding
                    let! challenge = Crypto.CodeChallenge.compute platform.crypto platform.encoding verifier
                    let authState =
                        { state = state
                          nonce = nonce
                          codeVerifier = verifier
                          redirectUri = opts.redirectUri }
                    Storage.AuthState.save platform.storage authState
                    let url = AuthorizeUrl.build platform.navigation doc opts state nonce challenge
                    platform.navigation.redirect url
                    // For non-browser platforms, callback params may already be available
                    match platform.navigation.getCallbackParams () with
                    | Some (code, callbackState) ->
                        platform.navigation.clearCallbackParams ()
                        return Some (code, callbackState)
                    | None ->
                        return None
                })
            ()
            (function
                | Some (code, state) -> AuthCallback (code, state)
                | None -> NoSession)
            (fun ex -> ValidationFailed (NetworkError ex))

module Logout =

    let cmd (nav: Navigation) (doc: DiscoveryDocument) (opts: Options) (idTokenHint: string option) : Cmd<Msg<'info>> =
        let encode = nav.encodeURIComponent
        match doc.endSessionEndpoint, opts.postLogoutRedirectUri with
        | Some endpoint, Some postLogoutUri ->
            Cmd.OfFunc.attempt
                (fun () ->
                    let url =
                        endpoint + "?"
                        + (match idTokenHint with
                           | Some token -> "id_token_hint=" + encode token + "&"
                           | None -> "")
                        + "post_logout_redirect_uri=" + encode postLogoutUri
                    nav.redirect url)
                ()
                (fun _ -> LoggedOut)
        | _ ->
            Cmd.ofMsg LoggedOut

let init (platform: Platform) (opts: Options) : Model<'info> * Cmd<Msg<'info>> =
    Initializing, Cmd.OfAsync.either (Discovery.fetch platform.http) opts.authority DiscoveryLoaded DiscoveryFailed

let update (platform: Platform) (opts: Options) (getUserInfo: string -> string -> Async<'info>) (msg: Msg<'info>) (model: Model<'info>) : Model<'info> * Cmd<Msg<'info>> =
    match model, msg with
    | Initializing, DiscoveryLoaded doc ->
        pendingDiscovery <- Some doc
        Initializing, Cmd.OfAsync.either (Token.Jwks.fetch platform.http) doc.jwksUri JwksLoaded JwksFailed

    | Initializing, JwksLoaded jwks ->
        match pendingDiscovery with
        | Some doc ->
            pendingDiscovery <- None
            match platform.navigation.getCallbackParams () with
            | Some (code, callbackState) ->
                platform.navigation.clearCallbackParams ()
                match Storage.AuthState.load platform.storage with
                | Some authState when authState.state = callbackState ->
                    pendingNonce <- Some authState.nonce
                    Ready (doc, jwks, ExchangingCode),
                    Cmd.OfAsync.either
                        (fun () -> Token.Code.exchange platform doc opts.clientId code authState.codeVerifier authState.redirectUri)
                        ()
                        TokenReceived
                        (fun ex -> ValidationFailed (TokenExchangeFailed ex.Message))
                | _ ->
                    Ready (doc, jwks, Unauthenticated), Cmd.none
            | None ->
                match Storage.StoredSession.load platform.storage with
                | Some response ->
                    Ready (doc, jwks, ValidatingToken),
                    Cmd.OfAsync.either
                        (fun () -> Token.IdToken.revalidateStored platform opts doc.issuer (nowEpoch ()) jwks response.idToken)
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

    | Ready (doc, jwks, ExchangingCode), TokenReceived response ->
        match pendingNonce with
        | Some nonce ->
            pendingNonce <- None
            Ready (doc, jwks, ValidatingToken),
            Cmd.OfAsync.either
                (fun () -> Token.IdToken.validate platform opts doc.issuer nonce (nowEpoch ()) jwks response.idToken)
                ()
                (fun result ->
                    match result with
                    | Ok payload -> TokenValidated (payload, response)
                    | Error err -> ValidationFailed (InvalidToken err))
                (fun ex -> ValidationFailed (NetworkError ex))
        | None ->
            Ready (doc, jwks, Unauthenticated), Cmd.none

    | Ready (doc, jwks, ValidatingToken), TokenValidated (payload, response) ->
        let session = Session.build response payload
        Ready (doc, jwks, Authenticated session),
        Cmd.batch [
            Cmd.OfFunc.attempt (Storage.StoredSession.save platform.storage) response (fun _ -> NoSession)
            Cmd.OfAsync.either
                (fun () -> getUserInfo doc.userinfoEndpoint session.accessToken)
                ()
                UserInfo
                UserInfoFailed
        ]

    | Ready (doc, jwks, _), ValidationFailed _ ->
        Storage.clearAll platform.storage
        Ready (doc, jwks, Unauthenticated), Cmd.none

    | Ready (doc, jwks, Authenticated session), UserInfo info ->
        Ready (doc, jwks, Authenticated { session with userInfo = Some info }), Cmd.none

    | Ready (doc, jwks, Authenticated session), UserInfoFailed _ ->
        Ready (doc, jwks, Authenticated session), Cmd.none

    | Ready (doc, jwks, Authenticated session), Tick ->
        let expiresInSeconds = int (session.expiresAt.ToUnixTimeSeconds() - nowEpoch ())
        if expiresInSeconds <= opts.renewBeforeExpirySeconds then
            Ready (doc, jwks, Renewing session),
            Cmd.OfAsync.either
                (fun () -> platform.renewal.renew doc opts jwks platform.storage)
                ()
                SilentRenewResult
                (fun ex -> SilentRenewResult (Error (NetworkError ex)))
        else
            Ready (doc, jwks, Authenticated session), Cmd.none

    | Ready (_, _, Renewing _), Tick ->
        model, Cmd.none

    | Ready (doc, jwks, Renewing session), SilentRenewResult (Ok (payload, response)) ->
        let newSession = Session.build response payload
        Ready (doc, jwks, Authenticated { newSession with userInfo = session.userInfo }),
        Cmd.OfFunc.attempt (Storage.StoredSession.save platform.storage) response (fun _ -> NoSession)

    | Ready (doc, jwks, Renewing session), SilentRenewResult (Error _) ->
        Ready (doc, jwks, Authenticated session), Cmd.none

    | Ready (doc, jwks, _), LogIn ->
        Ready (doc, jwks, Redirecting), Login.startCmd platform doc opts

    | Ready (doc, jwks, Redirecting), AuthCallback (code, callbackState) ->
        match Storage.AuthState.load platform.storage with
        | Some authState when authState.state = callbackState ->
            pendingNonce <- Some authState.nonce
            Ready (doc, jwks, ExchangingCode),
            Cmd.OfAsync.either
                (fun () -> Token.Code.exchange platform doc opts.clientId code authState.codeVerifier authState.redirectUri)
                ()
                TokenReceived
                (fun ex -> ValidationFailed (TokenExchangeFailed ex.Message))
        | _ ->
            Ready (doc, jwks, Unauthenticated), Cmd.none

    | Ready (doc, jwks, readyState), LogOut ->
        Storage.clearAll platform.storage
        let idTokenHint =
            match readyState with
            | Authenticated session -> Some session.idToken
            | Renewing session -> Some session.idToken
            | _ -> None
        Ready (doc, jwks, Unauthenticated), Logout.cmd platform.navigation doc opts idTokenHint

    | Ready (doc, jwks, _), LoggedOut ->
        Ready (doc, jwks, Unauthenticated), Cmd.none

    | _, DiscoveryFailed ex ->
        Failed (DiscoveryError ex), Cmd.none

    | _, JwksFailed ex ->
        Failed (DiscoveryError ex), Cmd.none

    | _ ->
        model, Cmd.none

let subscribe (platform: Platform) (model: Model<'info>) : Sub<Msg<'info>> =
    match model with
    | Ready (_, _, Authenticated _)
    | Ready (_, _, Renewing _) ->
        [ ["oidc"; "renewal"], Renewal.expirySubscription platform.timer ]
    | _ -> []
