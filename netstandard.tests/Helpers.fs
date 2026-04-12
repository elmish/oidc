module Tests.Helpers

open System
open System.Security.Cryptography
open Elmish.OIDC
open Elmish.OIDC.Types
open Thoth.Json.Net

type MemoryStorage() =
    let mutable store = Map.empty<string, string>
    interface Storage with
        member _.getItem key =
            store |> Map.tryFind key
        member _.setItem key value =
            store <- store |> Map.add key value
        member _.removeItem key =
            store <- store |> Map.remove key
    member _.Count = store.Count
    member _.ContainsKey key = store |> Map.containsKey key

let testOptions : Options =
    { clientId = "test-client-id"
      authority = "https://auth.example.com"
      scopes = [ "openid"; "profile" ]
      redirectUri = "https://app.example.com/callback"
      postLogoutRedirectUri = Some "https://app.example.com"
      silentRedirectUri = Some "https://app.example.com/silent"
      renewBeforeExpirySeconds = 60
      clockSkewSeconds = 300
      allowedAlgorithms = [ "RS256" ] }

let testDiscoveryDoc : DiscoveryDocument =
    { issuer = "https://auth.example.com"
      authorizationEndpoint = "https://auth.example.com/authorize"
      tokenEndpoint = "https://auth.example.com/token"
      userinfoEndpoint = "https://auth.example.com/userinfo"
      jwksUri = "https://auth.example.com/.well-known/jwks.json"
      endSessionEndpoint = Some "https://auth.example.com/logout" }

/// A mock Navigation that doesn't open a browser
let mockNavigation () =
    let mutable callbackParams : (string * string) option = None
    let nav =
        { new Navigation with
            member _.redirect (_url: string) = ()
            member _.getCallbackParams () = callbackParams
            member _.clearCallbackParams () = callbackParams <- None
            member _.encodeURIComponent (s: string) = Uri.EscapeDataString s }
    nav, (fun code state -> callbackParams <- Some (code, state))

/// A mock HttpClient that returns predefined responses
let mockHttp (responses: Map<string, string>) =
    { new HttpClient with
        member _.getText (url: string) =
            async {
                match responses |> Map.tryFind url with
                | Some text -> return text
                | None -> return failwith $"mockHttp: no response configured for GET {url}"
            }
        member _.postForm (url: string) (_body: string) =
            async {
                match responses |> Map.tryFind url with
                | Some text -> return text
                | None -> return failwith $"mockHttp: no response configured for POST {url}"
            } }

let testPlatform (storage: Storage) : Platform =
    let nav, _ = mockNavigation ()
    { crypto = DotNet.crypto
      encoding = DotNet.encoding
      http = mockHttp Map.empty
      navigation = nav
      renewal = { new RenewalStrategy with member _.renew _ _ _ _ = async { return Error (InvalidToken "not configured") } }
      storage = storage
      timer = DotNet.timer }

let testPlatformWith (storage: Storage) (http: HttpClient) (nav: Navigation) : Platform =
    { crypto = DotNet.crypto
      encoding = DotNet.encoding
      http = http
      navigation = nav
      renewal = { new RenewalStrategy with member _.renew _ _ _ _ = async { return Error (InvalidToken "not configured") } }
      storage = storage
      timer = DotNet.timer }

let jsonToBase64Url (json: string) : string =
    let bytes = Text.Encoding.UTF8.GetBytes json
    Crypto.base64UrlEncode DotNet.encoding bytes

let buildJwt (headerJson: string) (payloadJson: string) (signature: string) : string =
    let header = jsonToBase64Url headerJson
    let payload = jsonToBase64Url payloadJson
    $"{header}.{payload}.{signature}"

let buildTestJwt (header: JwtHeader) (payload: JwtPayload) : string =
    let headerJson =
        Encode.object [
            "alg", Encode.string header.alg
            "kid", Encode.string header.kid
        ] |> Encode.toString 0

    let payloadJson =
        Encode.object [
            "iss", Encode.string payload.iss
            "sub", Encode.string payload.sub
            "aud", payload.aud |> List.map Encode.string |> Encode.list
            "exp", Encode.int64 payload.exp
            "iat", Encode.int64 payload.iat
            yield! (match payload.nonce with
                    | Some n -> [ "nonce", Encode.string n ]
                    | None -> [])
        ] |> Encode.toString 0

    buildJwt headerJson payloadJson "dummysignature"

let generateTestKeyPair () : RSA * JwksKey =
    let rsa = RSA.Create(2048)
    let p = rsa.ExportParameters(true)
    let toB64Url (bytes: byte[]) = Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
    let jwksKey : JwksKey =
        { kty = "RSA"
          kid = "test-kid-1"
          n = toB64Url p.Modulus
          e = toB64Url p.Exponent
          alg = "RS256"
          ``use`` = "sig" }
    rsa, jwksKey

let signJwt (rsa: RSA) (headerJson: string) (payloadJson: string) : string =
    let header = jsonToBase64Url headerJson
    let payload = jsonToBase64Url payloadJson
    let signingInput = $"{header}.{payload}"
    let data = Text.Encoding.UTF8.GetBytes signingInput
    let signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
    let sigB64Url = Convert.ToBase64String(signature).Replace('+', '-').Replace('/', '_').TrimEnd('=')
    $"{signingInput}.{sigB64Url}"

let nowEpoch () : int64 =
    DateTimeOffset.UtcNow.ToUnixTimeSeconds()
