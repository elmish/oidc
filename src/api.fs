[<AutoOpen>]
module Elmish.OIDC.Api

open System

/// APIs for persisting our data across app instances
module internal Storage =
    open Fable.Import

    let clear key = 
        Browser.sessionStorage.removeItem key

    module Token =
        let get (ofStr:string->Result<Token,TokenError>) key = 
            Browser.sessionStorage.getItem key
            |> unbox<string>
            |> Option.ofObj
            |> function Some str -> ofStr str | _ -> Error NoToken
        
        let set (toStr:Token->string) key token =
            Browser.sessionStorage.setItem(key, toStr token)

    module Nonce =
        let set key (Nonce v) =
            Browser.sessionStorage.setItem(key, v)

        let get key = 
            Browser.sessionStorage.getItem key
            |> unbox<string>
            |> Option.ofObj
            |> Option.map Nonce

/// APIs for working with Token tokens and Nonces
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

    let concat (token:Token) = 
        let (Nonce nonce) = token.nonce
        [| token.idToken, "id_token"
           token.accessToken,"access_token"
           token.tokenType,"token_type"
           token.expiresIn,"expires_in"
           token.scope,"scope"
           token.state,"state"
           token.error,"error"
           nonce,"nonce"
           token.errorDesc,"error_description" |]
        |> Array.fold (fun s (v,k) -> sprintf "%s&%s=%s" s k v) ""
    
    let parse (hash:string) : Result<Token,TokenError> =
        let tokenize (str: string) = 
            match str.Split('=') with 
            | [| key; value |] -> (key,value) 
            | _ -> failwithf "Unable to parse: %s" str
        try
            let tokenComponents =
                hash.Split([|'&'|], StringSplitOptions.RemoveEmptyEntries)
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

    let serverOk (token:Token) =
        if System.String.IsNullOrEmpty token.error then Ok token else Error (ServerError (token.error,token.errorDesc))

    let expiryOk now (token:Token) = 
        if System.DateTime.Parse token.expiresIn < now then Ok token else Error Expired

    let nonceOk nonce (token:Token) =
        if nonce = token.nonce then Ok token else Error InvalidNonce

    let validate now nonce (token:Token) =
        result {
            // TODO: check signature
            let! ok = token |> serverOk
            let! ok = ok |> expiryOk now
            let! ok = ok |> nonceOk nonce // TODO: use nonce from returned claims
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
        let get decoder url (token:Token) : Promise<'info> =
            fetchAs<'info> (url+"/connect/userinfo")
                           decoder
                           [ requestHeaders (authenticatedJsonHeaders token.accessToken)
                             RequestProperties.Method HttpMethod.GET ]

    module Id =
        let login (opt:Options) (State state) (Nonce nonce) redirectTo = 
            Fable.Import.Browser.window.location.href <-
                sprintf "%s/connect/authorize?client_id=%s&response_type=%s&scope=%s&nonce=%s&state=%s&redirect_uri=%s"
                    opt.authority opt.clientId opt.responseType opt.scopes nonce state (Fable.Import.JS.encodeURIComponent redirectTo)

