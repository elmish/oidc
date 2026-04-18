namespace Elmish.OIDC

open System
open System.Net.Http
open System.Security.Cryptography
open System.Text
open Elmish.OIDC.Types

[<RequireQualifiedAccess>]
module DotNet =

    let crypto =
        let rng = RandomNumberGenerator.Create()
        { new CryptoProvider with
            member _.randomBytes len =
                let buf = Array.zeroCreate<byte> len
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
                    let nBytes = Crypto.Base64Url.decode key.n
                    let eBytes = Crypto.Base64Url.decode key.e
                    rsa.ImportParameters(RSAParameters(Modulus = nBytes, Exponent = eBytes))
                    return rsa :> obj
                }

            member _.rsaVerify (alg: string) (key: obj) (signature: byte[]) (data: byte[]) =
                async {
                    let rsa = key :?> RSA
                    let rsaAlg = Crypto.rsaAlgorithm alg
                    let hashAlg =
                        match rsaAlg.hash with
                        | "SHA-256" -> HashAlgorithmName.SHA256
                        | "SHA-384" -> HashAlgorithmName.SHA384
                        | "SHA-512" -> HashAlgorithmName.SHA512
                        | h -> HashAlgorithmName(h)
                    let padding =
                        if rsaAlg.name = "RSA-PSS" then RSASignaturePadding.Pss
                        else RSASignaturePadding.Pkcs1
                    return rsa.VerifyData(data, signature, hashAlg, padding)
                } }

    let http =
        let client = new System.Net.Http.HttpClient()
        { new HttpClient with
            member _.getText (url: string) =
                async {
                    let! response = client.GetAsync(url) |> Async.AwaitTask
                    response.EnsureSuccessStatusCode() |> ignore
                    return! response.Content.ReadAsStringAsync() |> Async.AwaitTask
                }

            member _.postForm (url: string) (body: string) =
                async {
                    use content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded")
                    let! response = client.PostAsync(url, content) |> Async.AwaitTask
                    response.EnsureSuccessStatusCode() |> ignore
                    return! response.Content.ReadAsStringAsync() |> Async.AwaitTask
                } }

    let httpWith (client: System.Net.Http.HttpClient) =
        { new HttpClient with
            member _.getText (url: string) =
                async {
                    let! response = client.GetAsync(url) |> Async.AwaitTask
                    response.EnsureSuccessStatusCode() |> ignore
                    return! response.Content.ReadAsStringAsync() |> Async.AwaitTask
                }

            member _.postForm (url: string) (body: string) =
                async {
                    use content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded")
                    let! response = client.PostAsync(url, content) |> Async.AwaitTask
                    response.EnsureSuccessStatusCode() |> ignore
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

    module Navigation =
        open System.Diagnostics
        open System.Net

        type private LoopbackState =
            { mutable callbackParams: (string * string) option }

        /// Creates a Navigation that uses RFC 8252 loopback redirect.
        /// `redirect` opens the system browser and starts an HttpListener on localhost to capture the callback.
        let loopback (port: int) =
            let redirectUri = $"http://127.0.0.1:{port}/"

            { new Navigation with
                member _.redirect (url: string) =
                    async {
                        // Start listener before opening browser
                        let listener = new HttpListener()
                        listener.Prefixes.Add(redirectUri)
                        listener.Start()

                        // Open system browser
                        Process.Start(ProcessStartInfo(url, UseShellExecute = true)) |> ignore

                        // Wait for the callback
                        let! context = listener.GetContextAsync() |> Async.AwaitTask
                        let query = context.Request.QueryString
                        let code = query.["code"]
                        let callbackState = query.["state"]

                        // Send response to browser
                        let response = context.Response
                        let body = Text.Encoding.UTF8.GetBytes("<html><body>Authentication complete. You can close this window.</body></html>")
                        response.ContentType <- "text/html"
                        response.ContentLength64 <- int64 body.Length
                        response.OutputStream.Write(body, 0, body.Length)
                        response.Close()
                        listener.Stop()

                        if not (isNull code) && not (isNull callbackState) then
                            return Some (code, callbackState)
                        else
                            return None
                    }

                member _.getCallbackParams () =
                    None

                member _.clearCallbackParams () =
                    ()

                member _.encodeURIComponent (s: string) =
                    Uri.EscapeDataString s }

        /// Creates a Navigation that uses a custom URI scheme callback.
        /// The app must register the scheme with the OS and call `setCallbackParams` when it receives the callback.
        let customScheme () =
            let state = { callbackParams = None }

            let nav =
                { new Navigation with
                    member _.redirect (url: string) =
                        async {
                            Process.Start(ProcessStartInfo(url, UseShellExecute = true)) |> ignore
                            return None
                        }

                    member _.getCallbackParams () =
                        state.callbackParams

                    member _.clearCallbackParams () =
                        state.callbackParams <- None

                    member _.encodeURIComponent (s: string) =
                        Uri.EscapeDataString s }

            // Return nav + setter for the callback params
            nav, (fun code callbackState -> state.callbackParams <- Some (code, callbackState))
