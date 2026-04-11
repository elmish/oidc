[<AutoOpen>]
module Elmish.OIDC.Token

open Fable.Core
open Thoth.Json

let private tokenResponseDecoder : Decoder<TokenResponse> =
    Decode.object (fun get ->
        { accessToken = get.Required.Field "access_token" Decode.string
          idToken = get.Required.Field "id_token" Decode.string
          tokenType = get.Required.Field "token_type" Decode.string
          expiresIn = get.Required.Field "expires_in" Decode.int
          scope = get.Required.Field "scope" Decode.string })

let private tokenErrorDecoder : Decoder<string> =
    Decode.object (fun get ->
        let error = get.Required.Field "error" Decode.string
        let desc = get.Optional.Field "error_description" Decode.string
        match desc with
        | Some d -> $"{error}: {d}"
        | None -> error)

let private jwtHeaderDecoder : Decoder<JwtHeader> =
    Decode.object (fun get ->
        { alg = get.Required.Field "alg" Decode.string
          kid = get.Required.Field "kid" Decode.string })

let private audDecoder : Decoder<string list> =
    Decode.oneOf
        [ Decode.list Decode.string
          Decode.string |> Decode.map (fun s -> [ s ]) ]

let private jwtPayloadDecoder : Decoder<JwtPayload> =
    Decode.object (fun get ->
        { iss = get.Required.Field "iss" Decode.string
          sub = get.Required.Field "sub" Decode.string
          aud = get.Required.Field "aud" audDecoder
          exp = get.Required.Field "exp" Decode.int64
          iat = get.Required.Field "iat" Decode.int64
          nonce = get.Optional.Field "nonce" Decode.string })

let private jwksKeyDecoder : Decoder<JwksKey> =
    Decode.object (fun get ->
        { kty = get.Required.Field "kty" Decode.string
          kid = get.Required.Field "kid" Decode.string
          n = get.Required.Field "n" Decode.string
          e = get.Required.Field "e" Decode.string
          alg = get.Required.Field "alg" Decode.string
          ``use`` = get.Required.Field "use" Decode.string })

let private jwksDecoder : Decoder<Jwks> =
    Decode.object (fun get ->
        { keys = get.Required.Field "keys" (Decode.list jwksKeyDecoder) })

let exchangeCode (doc: DiscoveryDocument) (clientId: string) (code: string) (codeVerifier: string) (redirectUri: string) : JS.Promise<TokenResponse> =
    let encode = Browser.Dom.window.encodeURIComponent
    let body =
        [ "grant_type", "authorization_code"
          "code", code
          "client_id", clientId
          "code_verifier", codeVerifier
          "redirect_uri", redirectUri ]
        |> List.map (fun (k, v) -> $"{encode k}={encode v}")
        |> String.concat "&"

    Interop.Http.postForm doc.tokenEndpoint body
    |> Promise.bind (fun response -> response.text())
    |> Promise.map (fun text ->
        match Decode.fromString tokenErrorDecoder text with
        | Ok errMsg -> failwith errMsg
        | Error _ ->
            match Decode.fromString tokenResponseDecoder text with
            | Ok resp -> resp
            | Error err -> failwith $"Failed to decode token response: {err}")

let fetchJwks (jwksUri: string) : JS.Promise<Jwks> =
    Interop.Http.get jwksUri
    |> Promise.bind (fun response -> response.text())
    |> Promise.map (fun text ->
        match Decode.fromString jwksDecoder text with
        | Ok jwks -> jwks
        | Error err -> failwith $"Failed to decode JWKS: {err}")

let decodeJwt (jwt: string) : Result<JwtHeader * JwtPayload, string> =
    let parts = jwt.Split('.')

    if parts.Length <> 3 then
        Error "JWT must have exactly 3 parts"
    else
        let headerJson = parts.[0] |> base64UrlDecode |> Interop.Encoding.fromBytes
        let payloadJson = parts.[1] |> base64UrlDecode |> Interop.Encoding.fromBytes

        match Decode.fromString jwtHeaderDecoder headerJson, Decode.fromString jwtPayloadDecoder payloadJson with
        | Ok header, Ok payload -> Ok(header, payload)
        | Error err, _ -> Error $"Failed to decode JWT header: {err}"
        | _, Error err -> Error $"Failed to decode JWT payload: {err}"

let verifySignature (key: obj) (jwt: string) : JS.Promise<bool> =
    let parts = jwt.Split('.')
    let signedData = parts.[0] + "." + parts.[1]
    let signatureBytes = base64UrlDecode parts.[2]
    Interop.Crypto.verify key (Interop.Buffers.toArrayBuffer signatureBytes) (Interop.Encoding.toArrayBuffer signedData)

let validateClaims
    (opts: Options)
    (nonce: string option)
    (nowEpoch: int64)
    (header: JwtHeader)
    (payload: JwtPayload)
    : Result<unit, string> =
    if not (opts.allowedAlgorithms |> List.contains header.alg) then
        Error $"Algorithm '{header.alg}' is not allowed. Allowed: {opts.allowedAlgorithms}"
    elif payload.iss <> opts.authority.TrimEnd('/') then
        Error $"Issuer mismatch: expected '{opts.authority.TrimEnd('/')}', got '{payload.iss}'"
    elif not (payload.aud |> List.contains opts.clientId) then
        Error $"Audience does not contain '{opts.clientId}'"
    elif payload.exp + int64 opts.clockSkewSeconds <= nowEpoch then
        Error "Token has expired"
    elif payload.iat - int64 opts.clockSkewSeconds > nowEpoch then
        Error "Token issued in the future"
    else
        match nonce with
        | Some n when payload.nonce <> Some n ->
            Error $"Nonce mismatch: expected '{n}'"
        | _ -> Ok()

let private validateAndVerify
    (opts: Options)
    (nonce: string option)
    (nowEpoch: int64)
    (jwt: string)
    (jwks: Jwks)
    : JS.Promise<Result<JwtPayload, string>> =
    match decodeJwt jwt with
    | Error err -> Promise.lift (Error err)
    | Ok(header, payload) ->
        match validateClaims opts nonce nowEpoch header payload with
        | Error err -> Promise.lift (Error err)
        | Ok() ->
            match jwks.keys |> List.tryFind (fun k -> k.kid = header.kid && k.``use`` = "sig") with
            | None -> Promise.lift (Error $"No signing key found for kid '{header.kid}'")
            | Some jwkKey ->
                Interop.Crypto.importJwk (jwkKey :> obj)
                |> Promise.bind (fun cryptoKey ->
                    verifySignature cryptoKey jwt
                    |> Promise.map (fun valid ->
                        if valid then Ok payload
                        else Error "Signature verification failed"))

let validateIdToken (opts: Options) (nonce: string) (nowEpoch: int64) (jwt: string) (jwks: Jwks) : JS.Promise<Result<JwtPayload, string>> =
    validateAndVerify opts (Some nonce) nowEpoch jwt jwks

let revalidateStoredToken (opts: Options) (nowEpoch: int64) (jwt: string) (jwks: Jwks) : JS.Promise<Result<JwtPayload, string>> =
    validateAndVerify opts None nowEpoch jwt jwks
