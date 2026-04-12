[<RequireQualifiedAccess>]
module Elmish.OIDC.DotNet

open System
open System.Net.Http
open System.Security.Cryptography
open System.Text
open Elmish.OIDC.Types

let crypto =
    { new CryptoProvider with
        member _.randomBytes len =
            let buf = Array.zeroCreate<byte> len
            use rng = RandomNumberGenerator.Create()
            rng.GetBytes buf
            buf

        member _.sha256 (data: byte[]) =
            async {
                use sha = SHA256.Create()
                return sha.ComputeHash data
            }

        member _.importRsaKey (key: JwksKey) =
            async {
                let rsa = RSA.Create()
                let nBytes = Convert.FromBase64String(Crypto.base64UrlToBase64 key.n)
                let eBytes = Convert.FromBase64String(Crypto.base64UrlToBase64 key.e)
                rsa.ImportParameters(RSAParameters(Modulus = nBytes, Exponent = eBytes))
                return rsa :> obj
            }

        member _.rsaVerify (key: obj) (signature: byte[]) (data: byte[]) =
            async {
                let rsa = key :?> RSA
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            } }

let encoding =
    { new EncodingProvider with
        member _.utf8Encode (s: string) =
            Encoding.UTF8.GetBytes s

        member _.utf8Decode (bytes: byte[]) =
            Encoding.UTF8.GetString bytes

        member _.base64Encode (bytes: byte[]) =
            Convert.ToBase64String bytes

        member _.base64Decode (s: string) =
            Convert.FromBase64String s }

let http =
    let client = new System.Net.Http.HttpClient()
    { new HttpClient with
        member _.getText (url: string) =
            client.GetStringAsync(url) |> Async.AwaitTask

        member _.postForm (url: string) (body: string) =
            async {
                use content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded")
                let! response = client.PostAsync(url, content) |> Async.AwaitTask
                return! response.Content.ReadAsStringAsync() |> Async.AwaitTask
            } }

let httpWith (client: System.Net.Http.HttpClient) =
    { new HttpClient with
        member _.getText (url: string) =
            client.GetStringAsync(url) |> Async.AwaitTask

        member _.postForm (url: string) (body: string) =
            async {
                use content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded")
                let! response = client.PostAsync(url, content) |> Async.AwaitTask
                return! response.Content.ReadAsStringAsync() |> Async.AwaitTask
            } }

let timer =
    { new TimerProvider with
        member _.createInterval (callback: unit -> unit) (ms: int) =
            let t = new System.Timers.Timer(float ms, AutoReset = true)
            t.Elapsed.Add(fun _ -> callback ())
            t.Start()
            { new IDisposable with
                member _.Dispose() =
                    t.Stop()
                    t.Dispose() }

        member _.createTimeout (callback: unit -> unit) (ms: int) =
            let t = new System.Timers.Timer(float ms, AutoReset = false)
            t.Elapsed.Add(fun _ -> callback ())
            t.Start()
            { new IDisposable with
                member _.Dispose() =
                    t.Stop()
                    t.Dispose() } }

type MemoryStorage() =
    let mutable store = Map.empty<string, string>
    interface Storage with
        member _.getItem key =
            store |> Map.tryFind key
        member _.setItem key value =
            store <- store |> Map.add key value
        member _.removeItem key =
            store <- store |> Map.remove key

let memoryStorage () = MemoryStorage() :> Storage
