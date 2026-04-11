module Tests.Helpers

open Elmish.OIDC.Types
open Elmish.OIDC.Storage
open Fable.Core
open Fable.Core.JsInterop
open Thoth.Json

type MemoryStorage() =
    let mutable store = Map.empty<string, string>
    interface IStorage with
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

let jsonToBase64Url (json: string) : string =
    let bytes : byte[] = Fable.Core.JsInterop.emitJsExpr json "new TextEncoder().encode($0)"
    Elmish.OIDC.Crypto.base64UrlEncode bytes

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

let generateTestKeyPair () : JS.Promise<obj * JwksKey> =
    emitJsExpr
        ()
        """(async () => {
            const keyPair = await crypto.subtle.generateKey(
                { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
                true,
                ['sign', 'verify']
            );
            const pubJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
            return [keyPair.privateKey, { kty: pubJwk.kty, kid: 'test-kid-1', n: pubJwk.n, e: pubJwk.e, alg: 'RS256', use: 'sig' }];
        })()"""

let signJwt (privateKey: obj) (headerJson: string) (payloadJson: string) : JS.Promise<string> =
    let header = jsonToBase64Url headerJson
    let payload = jsonToBase64Url payloadJson
    let signingInput = $"{header}.{payload}"
    emitJsExpr
        (privateKey, signingInput)
        """(async () => {
            const data = new TextEncoder().encode($1);
            const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', $0, data);
            const bytes = new Uint8Array(sig);
            let binary = '';
            for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
            const b64 = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            return $1 + '.' + b64;
        })()"""

let nowEpoch () : int64 =
    System.DateTimeOffset.UtcNow.ToUnixTimeSeconds()
