[<AutoOpen>]
module Elmish.OIDC.State

open Types
open Elmish

let init (cmd:Commands<_>) (jwt:string option) =
    let model = 
        match jwt with
        | Some jwt -> Callback jwt
        | _ -> Resuming
    model, cmd.loadNonce()

let update (cmd:Commands<_>) (mkStatus:Status<_>) model msg =
    match model, msg with
    | Callback jwt, NonceLoaded nonce -> 
        NewSession nonce, cmd.parseToken jwt

    | Resuming, NonceLoaded nonce -> 
        NewSession nonce, cmd.loadToken()

    | NewSession nonce, Token token -> 
        Validating, cmd.validateToken nonce token 

    | Validating, Token token ->
        Validated token,
        Cmd.batch [ cmd.storeToken token
                    cmd.getInfo token ]

    | Validated token, UserInfo info ->
        InfoLoaded (token,info), Cmd.none

    | _, LogIn state ->
        Unauthenticated, cmd.login state
    
    | _, LogOut ->
        Unauthenticated, cmd.logout()

    | _, NoNonce
    | _, LoggedOut -> 
        Unauthenticated, Cmd.none

    | _, UserInfoError _ ->
        model, Cmd.none

    | _, TokenError _ -> 
        Unauthenticated, Cmd.none

    | _, Status _ -> 
        model, Cmd.none

    | _, _ ->
        model, Cmd.ofMsg (sprintf "Invalid operation: %A (in %A state)" msg model |> mkStatus.warn |> Status)

[<Literal>]
let internal NonceKey = "oidc:nonce"

[<Literal>]
let internal JwtKey = "oidc:token"

/// Default constructor for `init` and `update` functions, and `Commands` API.
/// authority: Base URL for the oAuth2/OIDC authority
/// clientId: the app id known to the authority
/// scopes: scopes to request
/// mkStatus: constructors for Status messages
/// infoDecoder: Thoth.Json decoder for your 'info type
let mkDefault 
        (opt:Options)
        (mkStatus:Status<'status>)
        (infoDecoder:Thoth.Json.Decode.Decoder<'info>)
        : (string option -> Model<'info>*Cmd<Msg<'status,'info>>)
           * (Model<'info> -> Msg<'status,'info> -> Model<'info>*Cmd<Msg<'status,'info>>)
           * Commands<Msg<'status,'info>> =
    
    let ofTokenResult ok r = 
        match r with
        | Ok token -> ok token
        | Error err -> TokenError err
    let ofNonceOption r = 
        match r with
        | Some nonce -> NonceLoaded nonce
        | _ -> NoNonce
    let cmd =
        { getInfo = fun token -> 
            Cmd.ofPromise (Authority.Info.get infoDecoder opt.authority) token UserInfo UserInfoError 

          logout = fun _ -> 
            Cmd.ofFunc
                (fun _ -> 
                    Storage.clear NonceKey
                    Storage.clear JwtKey)
                ()
                (fun _ -> LoggedOut)
                (mkStatus.failure >> Status)

          login = fun state -> 
            Cmd.attemptFunc 
                (fun location ->
                    let nonce = Token.nextNonce()
                    Storage.Nonce.set NonceKey nonce
                    Authority.Id.login opt state nonce location)
                Fable.Import.Browser.window.location.href
                (mkStatus.failure >> Status)

          loadToken = fun _ ->
            Cmd.ofFunc (Storage.Token.get Token.parse) JwtKey (ofTokenResult Token) (mkStatus.failure >> Status) 

          storeToken = fun token -> 
            Cmd.attemptFunc (Storage.Token.set Token.concat JwtKey) token (mkStatus.failure >> Status) 

          parseToken = fun jwt ->
            Cmd.ofFunc Token.parse jwt (ofTokenResult Token) (mkStatus.failure >> Status)

          validateToken = fun nonce token ->
            Cmd.ofFunc (Token.validate System.DateTime.Now nonce) token (ofTokenResult ValidToken) (mkStatus.failure >> Status) 

          loadNonce = fun _ ->
            Cmd.ofFunc Storage.Nonce.get NonceKey ofNonceOption (mkStatus.failure >> Status) }
    
    init cmd, update cmd mkStatus, cmd    