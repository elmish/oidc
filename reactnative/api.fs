namespace Elmish.OIDC

open Elmish.OIDC.Types

module Api =

    let create (navigation: Navigation) (storage: Storage) (opts: Options) =
        let p =
            { crypto = ReactNative.crypto
              http = ReactNative.http
              navigation = navigation
              renewal = Unchecked.defaultof<RenewalStrategy>
              storage = storage
              timer = ReactNative.timer }
        let platform = { p with renewal = Renewal.refreshToken p }
        {|
            init = State.init platform opts
            update = State.update platform opts
            subscribe = State.subscribe platform 
        |}