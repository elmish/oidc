module internal Elmish.OIDC.ReactNativeInterop

open Fable.Core
open Fable.Core.JsInterop

module Crypto =

    [<Emit("globalThis.crypto.getRandomValues($0)")>]
    let getRandomValues (_buf: byte[]) : byte[] = jsNative

    // RSA verify via react-native-quick-crypto's Node-style API.
    // RNQC v0.7's SubtleCrypto.verify has RSA entirely commented out (only ECDSA works).
    // RNQC's createPublicKey({format:'jwk'}) is also broken (isJwk path commented out).
    // Working path: subtle.importKey (JWK→CryptoKey) → subtle.exportKey('spki') → DER buffer
    // → createVerify with {key: derBuf, format:'der', type:'spki'}.
    [<ImportAll("react-native-quick-crypto")>]
    let private rnqc : obj = jsNative

    [<Emit("""(function(rnqc, jwkIn, sigIn, dataIn, hashAlg, saltLen, algNameIn) {
    var B = globalThis.Buffer;
    var jwk2 = {kty: jwkIn.kty, n: jwkIn.n, e: jwkIn.e, alg: jwkIn.alg, ext: true};
    return globalThis.crypto.subtle.importKey('jwk', jwk2, {name: algNameIn, hash: hashAlg}, true, ['verify'])
        .then(function(cryptoKey) { return globalThis.crypto.subtle.exportKey('spki', cryptoKey); })
        .then(function(spkiBuf) {
            var verifier = rnqc.createVerify(hashAlg.replace('-', ''));
            verifier.update(B.from(new Uint8Array(dataIn)));
            var keyOpts = {key: B.from(spkiBuf), format: 'der', type: 'spki'};
            if (saltLen > 0) { keyOpts.padding = rnqc.constants.RSA_PKCS1_PSS_PADDING; keyOpts.saltLength = saltLen; }
            return verifier.verify(keyOpts, B.from(new Uint8Array(sigIn)));
        });
})($6, $0, $1, $2, $3, $4, $5)""")>]
    let private verifyImpl (_jwk: obj) (_signature: byte[]) (_data: byte[]) (_hashAlg: string) (_saltLength: int) (_algName: string) (_rnqc: obj) : JS.Promise<bool> = jsNative

    let verify (jwk: obj) (signature: byte[]) (data: byte[]) (hashAlg: string) (saltLength: int) (algName: string) : JS.Promise<bool> =
        verifyImpl jwk signature data hashAlg saltLength algName rnqc

    [<Emit("(typeof globalThis !== 'undefined' && globalThis.crypto != null && globalThis.crypto.subtle != null)")>]
    let isAvailable () : bool = jsNative

module Buffers =

    [<Emit("new Uint8Array($0)")>]
    let toBytes (_buf: JS.ArrayBuffer) : byte[] = jsNative

    [<Emit("$0.buffer")>]
    let toArrayBuffer (_bytes: byte[]) : JS.ArrayBuffer = jsNative

module Http =

    type Response =
        abstract ok: bool
        abstract status: int
        abstract statusText: string
        abstract text: unit -> JS.Promise<string>

    [<Emit("fetch($0)")>]
    let get (_url: string) : JS.Promise<Response> = jsNative

    [<Emit("fetch($0, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: $1 })")>]
    let postForm (_url: string) (_body: string) : JS.Promise<Response> = jsNative

module UrlSearchParams =

    [<Emit("new URLSearchParams($0)")>]
    let create (_query: string) : obj = jsNative

    [<Emit("$1.get($0)")>]
    let private get (_key: string) (_ps: obj) : string = jsNative

    let tryGet (key: string) (ps: obj) : string option =
        let v = get key ps
        if isNull v then None else Some v

module Linking =

    [<Emit("encodeURIComponent($0)")>]
    let encodeURIComponent (_s: string) : string = jsNative

module WebBrowser =

    type AuthSessionResult =
        abstract ``type``: string
        abstract url: string

    [<ImportMember("expo-web-browser")>]
    let openAuthSessionAsync (_url: string) (_redirectUrl: string) : JS.Promise<AuthSessionResult> = jsNative

    [<ImportMember("expo-web-browser")>]
    let openBrowserAsync (_url: string) : JS.Promise<obj> = jsNative
