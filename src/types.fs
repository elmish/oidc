[<AutoOpen>]
module Elmish.OIDC.Types

/// Secure state string
type State = State of string
/// JWT string
type JWT = JWT of string

/// Authorization response
type AuResponse =
    { idToken: JWT
      accessToken: JWT
      tokenType: string
      expires: System.DateTime
      scope: string
      state: State
      error: string
      errorDesc: string } 

type Model<'info> =
    | Resuming
    | Callback of string
    | NewSession of State
    | Validating
    | Unauthenticated
    | Validated of AuResponse
    | InfoLoaded of AuResponse * userInfo: 'info

/// Component message type
/// 'status: opaque type for external handling of status 
/// 'info: opaque type for external handling of user info
type Msg<'status,'info> =
    | Status of 'status
    | LogIn
    | LogOut
    | LoggedOut
    | StateLoaded of State
    | NoState
    | Response of AuResponse
    | ValidToken of AuResponse
    | ResponseError of ResponseError
    | UserInfo of 'info
    | UserInfoError of exn

and ResponseError =
    | NoResponse
    | ParsingError of exn
    | InvalidState
    | Expired
    | ServerError of string * string

/// Commands used by `init` and `update`
type Commands<'msg> =
    { getInfo: AuResponse -> Elmish.Cmd<'msg>
      login: unit -> Elmish.Cmd<'msg>
      logout: unit -> Elmish.Cmd<'msg>
      loadResponse: unit -> Elmish.Cmd<'msg>
      storeResponse: AuResponse -> Elmish.Cmd<'msg>
      parseResponse: string -> Elmish.Cmd<'msg>
      validateResponse: State -> AuResponse -> Elmish.Cmd<'msg>
      loadState: unit -> Elmish.Cmd<'msg> }

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
      scopes: string list }

