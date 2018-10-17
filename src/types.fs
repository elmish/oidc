[<AutoOpen>]
module Elmish.OIDC.Types

/// Secure nonce string
type Nonce = Nonce of string
type State = State of string

/// Authorization response token
type Token =
    { idToken: string
      accessToken: string
      tokenType: string
      expiresIn: string
      scope: string
      state: string
      error: string
      nonce: Nonce
      errorDesc: string } 

type Model<'info> =
    | Resuming
    | Callback of string
    | NewSession of Nonce
    | Validating
    | Unauthenticated
    | Validated of Token
    | InfoLoaded of Token * userInfo: 'info

/// Component message type
/// 'status: opaque type for external handling of status 
/// 'info: opaque type for external handling of user info
type Msg<'status,'info> =
    | Status of 'status
    | NonceLoaded of Nonce
    | LogIn of State
    | LogOut
    | LoggedOut
    | NoNonce
    | Token of Token
    | ValidToken of Token
    | TokenError of TokenError
    | UserInfo of 'info
    | UserInfoError of exn

and TokenError =
    | NoToken
    | ParsingError of exn
    | InvalidNonce
    | Expired
    | ServerError of string * string

/// Commands used by `init` and `update`
type Commands<'msg> =
    { getInfo: Token -> Elmish.Cmd<'msg>
      login: State -> Elmish.Cmd<'msg>
      logout: unit -> Elmish.Cmd<'msg>
      loadToken: unit -> Elmish.Cmd<'msg>
      storeToken: Token -> Elmish.Cmd<'msg>
      parseToken: string -> Elmish.Cmd<'msg>
      validateToken: Nonce -> Token -> Elmish.Cmd<'msg>
      loadNonce: unit -> Elmish.Cmd<'msg> }

/// Constructors for building 'status instances
type Status<'status> = 
    { info: string -> 'status
      warn: string -> 'status
      failure: exn -> 'status }

/// Authentication Options 
type Options = 
    { responseType: string
      authority: string
      clientId: string
      scopes: string }

