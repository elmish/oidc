[<AutoOpen>]
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
      ``use``: string }

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
      scope: string }

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

