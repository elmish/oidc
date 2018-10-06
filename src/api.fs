[<AutoOpen>]
module Elmish.OIDC.Api

open System

/// APIs for persisting our data across app instances
module internal Storage =
    open Fable.Import

    let clear key = 
        Browser.sessionStorage.removeItem key

    module Token =
        let get (ofStr:string->Result<JWT,TokenError>) key = 
            Browser.sessionStorage.getItem key
            |> unbox<string>
            |> Option.ofObj
            |> function Some str -> ofStr str | _ -> Error NoToken
        
        let set (toStr:JWT->string) key token =
            Browser.sessionStorage.setItem(key, toStr token)

    module Nonce =
        let set key (Nonce v) =
            Browser.sessionStorage.setItem(key, v)

        let get key = 
            Browser.sessionStorage.getItem key
            |> unbox<string>
            |> Option.ofObj
            |> Option.map Nonce

/// APIs for working with JWT tokens and Nonces
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module internal Token =
    open Fable.Core.JsInterop
    open Fable.PowerPack.Result

    let internal charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._~"
    let internal randomString len = 
        let bytes = Array.zeroCreate<byte> len
        Fable.Import.Browser.window.crypto?getRandomValues(bytes)
        bytes |> Array.map (fun b -> charset.[(int b) % charset.Length]) |> System.String |> string

    let nextNonce () = 
        randomString 16 |> Nonce

    let concat (jwt:JWT) = 
        let (Nonce nonce) = jwt.nonce
        [| jwt.idToken, "id_token"
           jwt.accessToken,"access_token"
           jwt.tokenType,"token_type"
           jwt.expiresIn,"expires_in"
           jwt.scope,"scope"
           jwt.state,"state"
           jwt.error,"error"
           nonce,"nonce"
           jwt.errorDesc,"error_description" |]
        |> Array.fold (fun s (v,k) -> sprintf "%s&%s=%s" s k v) ""
    
    let parse (jwt:string) : Result<JWT,TokenError> =
        let tokenize (str: string) = 
            match str.Split('=') with 
            | [| key; value |] -> (key,value) 
            | _ -> failwithf "Unable to parse: %s" str
        try
            let tokenComponents =
                jwt.Split([|'&'|], StringSplitOptions.RemoveEmptyEntries)
                |> Array.map tokenize |> dict
            Ok { idToken = tokenComponents.["id_token"]
                 accessToken = tokenComponents.["access_token"]
                 tokenType = tokenComponents.["token_type"]
                 expiresIn = tokenComponents.["expires_in"]
                 scope = tokenComponents.["scope"]
                 state = tokenComponents.["state"]
                 error = tokenComponents.["error"]
                 nonce = Nonce tokenComponents.["nonce"]
                 errorDesc = tokenComponents.["error_description"] }
        with ex -> 
            Error (ParsingError ex)

    let serverOk (jwt:JWT) =
        if System.String.IsNullOrEmpty jwt.error then Ok jwt else Error (ServerError (jwt.error,jwt.errorDesc))

    let expiryOk now (jwt:JWT) = 
        if System.DateTime.Parse jwt.expiresIn < now then Ok jwt else Error Expired

    let nonceOk nonce (jwt:JWT) =
        if nonce = jwt.nonce then Ok jwt else Error InvalidNonce

    let validate now nonce (jwt:JWT) =
        result {
            let! ok = jwt |> serverOk
            let! ok = ok |> expiryOk now
            let! ok = ok |> nonceOk nonce
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
        let get decoder url (token:JWT) : Promise<'info> =
            fetchAs<'info> (url+"/connect/userinfo")
                           decoder
                           [ requestHeaders (authenticatedJsonHeaders token.accessToken)
                             RequestProperties.Method HttpMethod.GET ]

    module Id =
        let login (opt:Options) (State state) (Nonce nonce) redirectTo = 
            Fable.Import.Browser.window.location.href <-
                sprintf "%s/connect/authorize?client_id=%s&response_type=%s&scope=%s&nonce=%s&state=%s&redirect_uri=%s"
                    opt.authority opt.clientId opt.responseType opt.scopes nonce state (Fable.Import.JS.encodeURI redirectTo)

