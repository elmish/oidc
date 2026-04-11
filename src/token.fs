[<AutoOpen>]
module Elmish.OIDC.Token

open Fable.Core
open Fable.Core.JsInterop
open Thoth.Json

// --- Interop helpers ---

[<Emit("encodeURIComponent($0)")>]
let private encodeUri (s: string) : string = jsNative

[<Emit("fetch($0)")>]
let private fetchGet (url: string) : JS.Promise<obj> = jsNative

[<Emit("fetch($0, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: $1 })")>]
let private fetchPost (url: string) (body: string) : JS.Promise<obj> = jsNative

[<Emit("new TextDecoder().decode($0)")>]
let private decodeUtf8 (bytes: byte[]) : string = jsNative

[<Emit("new TextEncoder().encode($0).buffer")>]
let private toArrayBuffer (s: string) : JS.ArrayBuffer = jsNative

[<Emit("$0.buffer")>]
let private toBuffer (bytes: byte[]) : JS.ArrayBuffer = jsNative

[<Emit("crypto.subtle.importKey('jwk', {kty: $0.kty, n: $0.n, e: $0.e, alg: $0.alg, ext: true}, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['verify'])")>]
let importJwk (key: obj) : JS.Promise<obj> = jsNative

[<Emit("crypto.subtle.verify('RSASSA-PKCS1-v1_5', $0, $1, $2)")>]
let private subtleVerify (key: obj) (signature: JS.ArrayBuffer) (data: JS.ArrayBuffer) : JS.Promise<bool> = jsNative

// --- Decoders ---

let private tokenResponseDecoder : Decode.Decoder<TokenResponse> =
    Decode.object (fun get ->
        { accessToken = get.Required.Field "access_token" Decode.string
          idToken = get.Required.Field "id_token" Decode.string
          tokenType = get.Required.Field "token_type" Decode.string
          expiresIn = get.Required.Field "expires_in" Decode.int
          scope = get.Required.Field "scope" Decode.string })

let private tokenErrorDecoder : Decode.Decoder<string> =
    Decode.object (fun get ->
        let error = get.Required.Field "error" Decode.string
        let desc = get.Optional.Field "error_description" Decode.string
        match desc with
        | Some d -> $"{error}: {d}"
        | None -> error)

let private jwtHeaderDecoder : Decode.Decoder<JwtHeader> =
    Decode.object (fun get ->
        { alg = get.Required.Field "alg" Decode.string
          kid = get.Required.Field "kid" Decode.string })

let private audDecoder : Decode.Decoder<string list> =
    Decode.oneOf
        [ Decode.list Decode.string
          Decode.string |> Decode.map (fun s -> [ s ]) ]

let private jwtPayloadDecoder : Decode.Decoder<JwtPayload> =
    Decode.object (fun get ->
        { iss = get.Required.Field "iss" Decode.string
          sub = get.Required.Field "sub" Decode.string
          aud = get.Required.Field "aud" audDecoder
          exp = get.Required.Field "exp" Decode.int64
          iat = get.Required.Field "iat" Decode.int64
          nonce = get.Optional.Field "nonce" Decode.string })

let private jwksKeyDecoder : Decode.Decoder<JwksKey> =
    Decode.object (fun get ->
        { kty = get.Required.Field "kty" Decode.string
          kid = get.Required.Field "kid" Decode.string
          n = get.Required.Field "n" Decode.string
          e = get.Required.Field "e" Decode.string
          alg = get.Required.Field "alg" Decode.string
          ``use`` = get.Required.Field "use" Decode.string })

let private jwksDecoder : Decode.Decoder<Jwks> =
    Decode.object (fun get ->
        { keys = get.Required.Field "keys" (Decode.list jwksKeyDecoder) })

// --- Part 1: Token Exchange ---

let exchangeCode (doc: DiscoveryDocument) (clientId: string) (code: string) (codeVerifier: string) (redirectUri: string) : JS.Promise<TokenResponse> =
    let body =
        [ "grant_type", "authorization_code"
          "code", code
          "client_id", clientId
          "code_verifier", codeVerifier
          "redirect_uri", redirectUri ]
        |> List.map (fun (k, v) -> $"{encodeUri k}={encodeUri v}")
        |> String.concat "&"

    fetchPost doc.tokenEndpoint body
    |> Promise.bind (fun response -> response?text() : JS.Promise<string>)
    |> Promise.map (fun text ->
        match Decode.fromString tokenErrorDecoder text with
        | Ok errMsg -> failwith errMsg
        | Error _ ->
            match Decode.fromString tokenResponseDecoder text with
            | Ok resp -> resp
            | Error err -> failwith $"Failed to decode token response: {err}")

// --- Part 2: JWKS Fetch ---

let fetchJwks (jwksUri: string) : JS.Promise<Jwks> =
    fetchGet jwksUri
    |> Promise.bind (fun response -> response?text() : JS.Promise<string>)
    |> Promise.map (fun text ->
        match Decode.fromString jwksDecoder text with
        | Ok jwks -> jwks
        | Error err -> failwith $"Failed to decode JWKS: {err}")

// --- Part 3: JWT Decode ---

let decodeJwt (jwt: string) : Result<JwtHeader * JwtPayload, string> =
    let parts = jwt.Split('.')

    if parts.Length <> 3 then
        Error "JWT must have exactly 3 parts"
    else
        let headerJson = parts.[0] |> base64UrlDecode |> decodeUtf8
        let payloadJson = parts.[1] |> base64UrlDecode |> decodeUtf8

        match Decode.fromString jwtHeaderDecoder headerJson, Decode.fromString jwtPayloadDecoder payloadJson with
        | Ok header, Ok payload -> Ok(header, payload)
        | Error err, _ -> Error $"Failed to decode JWT header: {err}"
        | _, Error err -> Error $"Failed to decode JWT payload: {err}"

// --- Part 4: Signature Verification ---

let verifySignature (key: obj) (jwt: string) : JS.Promise<bool> =
    let parts = jwt.Split('.')
    let signedData = parts.[0] + "." + parts.[1]
    let signatureBytes = base64UrlDecode parts.[2]
    subtleVerify key (toBuffer signatureBytes) (toArrayBuffer signedData)

// --- Part 5: Validation Pipeline ---

let private validateClaims
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
                importJwk (jwkKey :> obj)
                |> Promise.bind (fun cryptoKey ->
                    verifySignature cryptoKey jwt
                    |> Promise.map (fun valid ->
                        if valid then Ok payload
                        else Error "Signature verification failed"))

let validateIdToken (opts: Options) (nonce: string) (nowEpoch: int64) (jwt: string) (jwks: Jwks) : JS.Promise<Result<JwtPayload, string>> =
    validateAndVerify opts (Some nonce) nowEpoch jwt jwks

let revalidateStoredToken (opts: Options) (nowEpoch: int64) (jwt: string) (jwks: Jwks) : JS.Promise<Result<JwtPayload, string>> =
    validateAndVerify opts None nowEpoch jwt jwks
