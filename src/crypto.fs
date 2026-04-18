[<RequireQualifiedAccess>]
module Elmish.OIDC.Crypto

open Elmish.OIDC.Types

type RsaAlgorithm =
    { name: string
      hash: string }

let rsaAlgorithm (alg: string) : RsaAlgorithm =
    match alg with
    | "RS256" -> { name = "RSASSA-PKCS1-v1_5"; hash = "SHA-256" }
    | "RS384" -> { name = "RSASSA-PKCS1-v1_5"; hash = "SHA-384" }
    | "RS512" -> { name = "RSASSA-PKCS1-v1_5"; hash = "SHA-512" }
    | "PS256" -> { name = "RSA-PSS"; hash = "SHA-256" }
    | "PS384" -> { name = "RSA-PSS"; hash = "SHA-384" }
    | "PS512" -> { name = "RSA-PSS"; hash = "SHA-512" }
    | _ -> failwith $"Unsupported RSA algorithm: {alg}"

let randomBytes (crypto: CryptoProvider) (len: int) : byte[] =
    crypto.randomBytes len

module Utf8 =

    // Pure F# UTF-8 encode/decode. TextEncoder is available in Hermes since RN 0.74,
    // but TextDecoder only since RN 0.85, so we can't rely on the Web APIs.
    // System.Text.Encoding.UTF8 on Fable ultimately calls TextEncoder/TextDecoder too.

    let encode (s: string) : byte[] =
        if System.String.IsNullOrEmpty s then [||] else
        let sLen = s.Length
        // First pass: compute byte length
        let mutable byteLen = 0
        let mutable i = 0
        while i < sLen do
            let c = int s.[i]
            if c < 0x80 then byteLen <- byteLen + 1; i <- i + 1
            elif c < 0x800 then byteLen <- byteLen + 2; i <- i + 1
            elif c >= 0xD800 && c <= 0xDBFF && i + 1 < sLen then byteLen <- byteLen + 4; i <- i + 2
            else byteLen <- byteLen + 3; i <- i + 1
        // Second pass: fill pre-allocated byte[] (Fable compiles to Uint8Array)
        let out = Array.zeroCreate<byte> byteLen
        let mutable j = 0
        i <- 0
        while i < sLen do
            let c = int s.[i]
            if c < 0x80 then
                out.[j] <- byte c
                j <- j + 1; i <- i + 1
            elif c < 0x800 then
                out.[j] <- byte (0xC0 ||| (c >>> 6))
                out.[j + 1] <- byte (0x80 ||| (c &&& 0x3F))
                j <- j + 2; i <- i + 1
            elif c >= 0xD800 && c <= 0xDBFF && i + 1 < sLen then
                let c2 = int s.[i + 1]
                let cp = 0x10000 + ((c - 0xD800) <<< 10) + (c2 - 0xDC00)
                out.[j] <- byte (0xF0 ||| (cp >>> 18))
                out.[j + 1] <- byte (0x80 ||| ((cp >>> 12) &&& 0x3F))
                out.[j + 2] <- byte (0x80 ||| ((cp >>> 6) &&& 0x3F))
                out.[j + 3] <- byte (0x80 ||| (cp &&& 0x3F))
                j <- j + 4; i <- i + 2
            else
                out.[j] <- byte (0xE0 ||| (c >>> 12))
                out.[j + 1] <- byte (0x80 ||| ((c >>> 6) &&& 0x3F))
                out.[j + 2] <- byte (0x80 ||| (c &&& 0x3F))
                j <- j + 3; i <- i + 1
        out

    let decode (bytes: byte[]) : string =
        if bytes.Length = 0 then "" else
        let sb = System.Text.StringBuilder(bytes.Length)
        let mutable i = 0
        let len = bytes.Length
        while i < len do
            let b0 = int bytes.[i]
            if b0 < 0x80 then
                sb.Append(char b0) |> ignore
                i <- i + 1
            elif b0 < 0xC0 then
                // Invalid continuation byte at start of sequence; emit replacement char
                sb.Append('\uFFFD') |> ignore
                i <- i + 1
            elif b0 < 0xE0 && i + 1 < len then
                let b1 = int bytes.[i + 1]
                let cp = ((b0 &&& 0x1F) <<< 6) ||| (b1 &&& 0x3F)
                sb.Append(char cp) |> ignore
                i <- i + 2
            elif b0 < 0xF0 && i + 2 < len then
                let b1 = int bytes.[i + 1]
                let b2 = int bytes.[i + 2]
                let cp = ((b0 &&& 0x0F) <<< 12) ||| ((b1 &&& 0x3F) <<< 6) ||| (b2 &&& 0x3F)
                sb.Append(char cp) |> ignore
                i <- i + 3
            elif b0 < 0xF8 && i + 3 < len then
                let b1 = int bytes.[i + 1]
                let b2 = int bytes.[i + 2]
                let b3 = int bytes.[i + 3]
                let cp =
                    ((b0 &&& 0x07) <<< 18)
                    ||| ((b1 &&& 0x3F) <<< 12)
                    ||| ((b2 &&& 0x3F) <<< 6)
                    ||| (b3 &&& 0x3F)
                // Encode as surrogate pair
                let cp' = cp - 0x10000
                sb.Append(char (0xD800 ||| (cp' >>> 10))) |> ignore
                sb.Append(char (0xDC00 ||| (cp' &&& 0x3FF))) |> ignore
                i <- i + 4
            else
                sb.Append('\uFFFD') |> ignore
                i <- i + 1
        sb.ToString()

module Base64Url =

    // Pure F# base64url implementation — no platform dependency, no btoa/atob.
    // Encodes directly to base64url (unpadded, URL-safe alphabet) and decodes
    // base64url with or without padding.

    let private alphabet =
        [| 'A';'B';'C';'D';'E';'F';'G';'H';'I';'J';'K';'L';'M';'N';'O';'P'
           'Q';'R';'S';'T';'U';'V';'W';'X';'Y';'Z';'a';'b';'c';'d';'e';'f'
           'g';'h';'i';'j';'k';'l';'m';'n';'o';'p';'q';'r';'s';'t';'u';'v'
           'w';'x';'y';'z';'0';'1';'2';'3';'4';'5';'6';'7';'8';'9';'-';'_' |]

    let private decodeChar (c: char) : int =
        let v = int c
        if v >= int 'A' && v <= int 'Z' then v - int 'A'
        elif v >= int 'a' && v <= int 'z' then v - int 'a' + 26
        elif v >= int '0' && v <= int '9' then v - int '0' + 52
        elif c = '-' || c = '+' then 62
        elif c = '_' || c = '/' then 63
        else -1

    let encode (bytes: byte[]) : string =
        let len = bytes.Length
        if len = 0 then "" else
        let full = len / 3
        let rem = len - full * 3
        let outLen = full * 4 + (if rem = 0 then 0 elif rem = 1 then 2 else 3)
        let out = Array.zeroCreate<char> outLen
        let mutable i = 0
        let mutable j = 0
        while i < full * 3 do
            let b0 = int bytes.[i]
            let b1 = int bytes.[i + 1]
            let b2 = int bytes.[i + 2]
            out.[j]     <- alphabet.[b0 >>> 2]
            out.[j + 1] <- alphabet.[((b0 &&& 0x3) <<< 4) ||| (b1 >>> 4)]
            out.[j + 2] <- alphabet.[((b1 &&& 0xF) <<< 2) ||| (b2 >>> 6)]
            out.[j + 3] <- alphabet.[b2 &&& 0x3F]
            i <- i + 3
            j <- j + 4
        if rem = 1 then
            let b0 = int bytes.[i]
            out.[j]     <- alphabet.[b0 >>> 2]
            out.[j + 1] <- alphabet.[(b0 &&& 0x3) <<< 4]
        elif rem = 2 then
            let b0 = int bytes.[i]
            let b1 = int bytes.[i + 1]
            out.[j]     <- alphabet.[b0 >>> 2]
            out.[j + 1] <- alphabet.[((b0 &&& 0x3) <<< 4) ||| (b1 >>> 4)]
            out.[j + 2] <- alphabet.[(b1 &&& 0xF) <<< 2]
        System.String(out)

    let decode (s: string) : byte[] =
        let mutable len = s.Length
        while len > 0 && s.[len - 1] = '=' do len <- len - 1
        if len = 0 then [||] else
        let rem = len % 4
        if rem = 1 then failwith "Invalid base64url: length mod 4 = 1"
        let full = len / 4
        let outLen = full * 3 + (if rem = 0 then 0 elif rem = 2 then 1 else 2)
        let out = Array.zeroCreate<byte> outLen
        let mutable i = 0
        let mutable j = 0
        while i < full * 4 do
            let c0 = decodeChar s.[i]
            let c1 = decodeChar s.[i + 1]
            let c2 = decodeChar s.[i + 2]
            let c3 = decodeChar s.[i + 3]
            if c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0 then
                failwith "Invalid base64url character"
            out.[j]     <- byte ((c0 <<< 2) ||| (c1 >>> 4))
            out.[j + 1] <- byte (((c1 &&& 0xF) <<< 4) ||| (c2 >>> 2))
            out.[j + 2] <- byte (((c2 &&& 0x3) <<< 6) ||| c3)
            i <- i + 4
            j <- j + 3
        if rem = 2 then
            let c0 = decodeChar s.[i]
            let c1 = decodeChar s.[i + 1]
            if c0 < 0 || c1 < 0 then failwith "Invalid base64url character"
            out.[j] <- byte ((c0 <<< 2) ||| (c1 >>> 4))
        elif rem = 3 then
            let c0 = decodeChar s.[i]
            let c1 = decodeChar s.[i + 1]
            let c2 = decodeChar s.[i + 2]
            if c0 < 0 || c1 < 0 || c2 < 0 then failwith "Invalid base64url character"
            out.[j]     <- byte ((c0 <<< 2) ||| (c1 >>> 4))
            out.[j + 1] <- byte (((c1 &&& 0xF) <<< 4) ||| (c2 >>> 2))
        out

module OAuthState =

    let generate (crypto: CryptoProvider) : string =
        randomBytes crypto 32 |> Base64Url.encode

module Nonce =

    let generate (crypto: CryptoProvider) : string =
        randomBytes crypto 32 |> Base64Url.encode

module CodeVerifier =

    let generate (crypto: CryptoProvider) : string =
        randomBytes crypto 32 |> Base64Url.encode

module CodeChallenge =

    let compute (crypto: CryptoProvider) (verifier: string) : Async<string> =
        async {
            let! hash = crypto.sha256 (Utf8.encode verifier)
            return Base64Url.encode hash
        }
