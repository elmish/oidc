[<AutoOpen>]
module Elmish.OIDC.Api

open System

/// APIs for persisting our data across app instances
module internal Storage =
    open Fable.Import

    let clear key = 
        Browser.sessionStorage.removeItem key

    module Response =
        let get (ofStr:string->Result<AuResponse,ResponseError>) key = 
            Browser.sessionStorage.getItem key
            |> unbox<string>
            |> Option.ofObj
            |> function Some str -> ofStr str | _ -> Error NoResponse
        
        let set (toStr:AuResponse->string) key response =
            Browser.sessionStorage.setItem(key, toStr response)

    module State =
        let set key (State v) =
            Browser.sessionStorage.setItem(key, v)

        let get key = 
            Browser.sessionStorage.getItem key
            |> unbox<string>
            |> Option.ofObj
            |> Option.map State

/// APIs for working with Response tokens and Nonces
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module internal Response =
    open Fable.Core.JsInterop
    open Fable.PowerPack.Result

    let internal charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._~"
    let internal randomString len = 
        let bytes = Array.zeroCreate<byte> len
        Fable.Import.Browser.window.crypto?getRandomValues(bytes)
        bytes |> Array.map (fun b -> charset.[(int b) % charset.Length]) |> System.String |> string

    let nextState () = 
        randomString 16 |> State

    let concat (response:AuResponse) = 
        let (State state) = response.state
        let (JWT accessToken) = response.accessToken
        let (JWT idToken) = response.idToken
        [| idToken, "id_token"
           accessToken,"access_token"
           response.tokenType,"token_type"
           (string response.expires),"expires_at"
           response.scope,"scope"
           state,"state"
           response.error,"error"
           response.errorDesc,"error_description" |]
        |> Array.fold (fun s (v,k) -> sprintf "%s&%s=%s" s k v) ""
    
    let parse (hash:string) : Result<AuResponse,ResponseError> =
        let tokenize (str: string) = 
            match str.Split('=') with 
            | [| key; value |] -> (key,value) 
            | _ -> failwithf "Unable to parse: %s" str
        try
            let xs =
                hash.Split([|'&'|], StringSplitOptions.RemoveEmptyEntries)
                |> Array.map tokenize |> dict
            Ok { idToken = JWT xs.["id_token"]
                 accessToken = JWT xs.["access_token"]
                 tokenType = xs.["token_type"]
                 expires = match xs.TryGetValue "expires_in" with 
                           | true,s ->  DateTime.Now + TimeSpan.FromSeconds(float s)
                           | _ -> (DateTime.Parse xs.["expires_at"])
                 scope = xs.["scope"]
                 state = State xs.["state"]
                 error = xs.["error"]
                 errorDesc = xs.["error_description"] }
        with ex -> 
            Error (ParsingError ex)

    let serverOk (response:AuResponse) =
        if System.String.IsNullOrEmpty response.error then Ok response else Error (ServerError (response.error,response.errorDesc))

    let expiryOk now (response:AuResponse) = 
        if response.expires > now then Ok response else Error Expired

    let stateOk state (response:AuResponse) =
        if state = response.state then Ok response else Error InvalidState

    let validate now nonce (response:AuResponse) =
        result {
            let! ok = response |> serverOk
            let! ok = ok |> expiryOk now
            let! ok = ok |> stateOk nonce
            return ok
        }

/// APIs for talking to oAuth2 endpoints
module internal Authority =
    open Fable.Import.JS
    open Fable.PowerPack.Fetch

    let authenticatedJsonHeaders accessToken =
        [ HttpRequestHeaders.Authorization <| sprintf "Bearer %s" accessToken
          HttpRequestHeaders.ContentType "application/json" ]

    module Info =
        let get decoder url (response:AuResponse) : Promise<'info> =
            let (JWT token) = response.accessToken
            fetchAs<'info> (url+"/connect/userinfo")
                           decoder
                           [ requestHeaders (authenticatedJsonHeaders token)
                             RequestProperties.Method HttpMethod.GET ]

    module Id =
        let login (opt:Options) (State state) redirectTo =
            let scopes = opt.scopes |> List.reduce (fun x y -> x + " " + y)
            Fable.Import.Browser.window.location.href <-
                sprintf "%s/connect/authorize?client_id=%s&response_type=%s&scope=%s&nonce=%s&state=%s&redirect_uri=%s"
                    opt.authority opt.clientId opt.responseType scopes state state (Fable.Import.JS.encodeURIComponent redirectTo)

