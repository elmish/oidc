module Elmish.OIDC.Types

open System

type Options =
    { clientId: string
      authority: string
      scopes: string list
      redirectUri: string
      postLogoutRedirectUri: string option
      silentRedirectUri: string option
      renewBeforeExpirySeconds: int
      clockSkewSeconds: int
      allowedAlgorithms: string list }

type DiscoveryDocument =
    { issuer: string
      authorizationEndpoint: string
      tokenEndpoint: string
      userinfoEndpoint: string
      jwksUri: string
      endSessionEndpoint: string option }

type JwksKey =
    { kty: string
      kid: string
      n: string
      e: string
      alg: string
      ``use``: string option }

type Jwks =
    { keys: JwksKey list }

type JwtHeader =
    { alg: string
      kid: string }

type JwtPayload =
    { iss: string
      sub: string
      aud: string list
      exp: int64
      iat: int64
      nonce: string option }

type TokenResponse =
    { accessToken: string
      idToken: string
      tokenType: string
      expiresIn: int
      scope: string
      refreshToken: string option }

type AuthState =
    { state: string
      nonce: string
      codeVerifier: string
      redirectUri: string }

type OidcError =
    | DiscoveryError of exn
    | IssuerMismatch of expected:string * actual:string
    | InvalidState
    | TokenExchangeFailed of string
    | InvalidToken of string
    | Expired
    | ServerError of error:string * description:string
    | NetworkError of exn

// Platform abstractions for cross-platform support

type Storage =
    abstract getItem: string -> string option
    abstract setItem: string -> string -> unit
    abstract removeItem: string -> unit

type CryptoProvider =
    abstract randomBytes: int -> byte[]
    abstract sha256: byte[] -> Async<byte[]>
    abstract importRsaKey: JwksKey -> Async<obj>
    abstract rsaVerify: alg:string -> key:obj -> signature:byte[] -> data:byte[] -> Async<bool>

type HttpClient =
    abstract getText: string -> Async<string>
    abstract postForm: string -> string -> Async<string>

type Navigation =
    abstract redirect: string -> Async<(string * string) option>
    abstract getCallbackParams: unit -> (string * string) option
    abstract clearCallbackParams: unit -> unit
    abstract encodeURIComponent: string -> string

type RenewalStrategy =
    abstract renew: DiscoveryDocument -> Options -> Jwks -> Storage -> Async<Result<JwtPayload * TokenResponse, OidcError>>

type TimerProvider =
    abstract createInterval: (unit -> unit) -> int -> IDisposable
    abstract createTimeout: (unit -> unit) -> int -> IDisposable

type Platform =
    { crypto: CryptoProvider
      http: HttpClient
      navigation: Navigation
      renewal: RenewalStrategy
      storage: Storage
      timer: TimerProvider }

type Session<'info> =
    { accessToken: string
      idToken: string
      tokenType: string
      expiresAt: DateTimeOffset
      scope: string
      claims: JwtPayload
      userInfo: 'info option }

type ReadyState<'info> =
    | ProcessingCallback of code:string * state:string
    | ExchangingCode
    | ValidatingToken
    | Unauthenticated
    | Redirecting
    | Authenticated of Session<'info>
    | Renewing of Session<'info>

type Model<'info> =
    | Initializing
    | Ready of DiscoveryDocument * Jwks * ReadyState<'info>
    | Failed of OidcError

type Msg<'info> =
    | DiscoveryLoaded of DiscoveryDocument
    | DiscoveryFailed of exn
    | JwksLoaded of Jwks
    | JwksFailed of exn
    | AuthCallback of code:string * state:string
    | TokenReceived of TokenResponse
    | TokenValidated of JwtPayload * TokenResponse
    | ValidationFailed of OidcError
    | UserInfo of 'info
    | UserInfoFailed of exn
    | SilentRenewResult of Result<(JwtPayload * TokenResponse), OidcError>
    | LogIn
    | LogOut
    | LoggedOut
    | SessionRestored of TokenResponse
    | NoSession
    | Tick

module Session =

    let build (response: TokenResponse) (payload: JwtPayload) : Session<'info> =
        { accessToken = response.accessToken
          idToken = response.idToken
          tokenType = response.tokenType
          expiresAt = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + int64 response.expiresIn)
          scope = response.scope
          claims = payload
          userInfo = None }

    let tryGet (model: Model<'info>) : Session<'info> option =
        match model with
        | Ready (_, _, Authenticated session)
        | Ready (_, _, Renewing session) -> Some session
        | _ -> None

    let isAuthenticated (model: Model<'info>) : bool =
        tryGet model |> Option.isSome

    let tryGetAccessToken (model: Model<'info>) : string option =
        tryGet model |> Option.map (fun s -> s.accessToken)

