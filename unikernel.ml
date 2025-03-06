open Lwt.Infix

module K = struct
  open Cmdliner

  let key =
    Arg.conv ~docv:"HOST:HASH:DATA"
      Dns.Dnskey.(name_key_of_string,
                  (fun ppf v -> Fmt.string ppf (name_key_to_string v)))

  let dns_key =
    let doc = Arg.info ~doc:"nsupdate key (name:type:value,...)" ["dns-key"] in
    Mirage_runtime.register_arg Arg.(value & opt (some key) None doc)

  let dns_server =
    let doc = Arg.info ~doc:"dns server IP" ["dns-server"] in
    Mirage_runtime.register_arg
      Arg.(value & opt (some Mirage_runtime_network.Arg.ip_address) None doc)

  let dns_port =
    let doc = Arg.info ~doc:"dns server port" ["dns-port"] in
    Mirage_runtime.register_arg Arg.(value & opt int 53 doc)

  let key =
    let doc = Arg.info ~doc:"certificate key (<type>:seed or b64)" ["key"] in
    Mirage_runtime.register_arg Arg.(value & opt (some string) None doc)

  let hostname =
    let doc = Arg.info ~doc:"Name of the unikernel" ["name"] in
    Arg.(value & opt string "retreat.mirageos.org" doc)

  let domain_name =
    Arg.conv ~docv:"DOMAIN NAME" (Domain_name.of_string, Domain_name.pp)

  let additional_hostnames =
    let doc = Arg.info ~doc:"Additional names of the unikernel" ["additional"] in
    Mirage_runtime.register_arg Arg.(value & opt_all domain_name [] doc)

  let host = Mirage_runtime.register_arg hostname

  let no_tls =
    let doc = Arg.info ~doc:"Disable TLS" [ "no-tls" ] in
    Mirage_runtime.register_arg Arg.(value & flag doc)

  let http_port =
    let doc = Arg.info ~doc:"Listening HTTP port." ["http"] ~docv:"PORT" in
    Mirage_runtime.register_arg Arg.(value & opt int 80 doc)

  let https_port =
    let doc = Arg.info ~doc:"Listening HTTPS port." ["https"] ~docv:"PORT" in
    Mirage_runtime.register_arg Arg.(value & opt int 443 doc)
end

module Main (S : Tcpip.Stack.V4V6) (Management : Tcpip.Stack.V4V6) = struct
  module Dns_certify = Dns_certify_mirage.Make(S)
  module TLS = Tls_mirage.Make(S.TCP)

  let http_header ~status xs =
    let headers = List.map (fun (k, v) -> k ^ ": " ^ v) xs in
    let lines = status :: headers @ [ "\r\n" ] in
    Cstruct.of_string (String.concat "\r\n" lines)

  let header len = http_header
      ~status:"HTTP/1.1 200 OK"
      [ ("Content-Type", "text/html; charset=UTF-8") ;
        ("Content-length", string_of_int len) ;
        ("Connection", "close") ]

  let incr_access =
    let s = ref 0 in
    let open Metrics in
    let doc = "access statistics" in
    let data () =
      Data.v [
        int "total http responses" !s ;
      ] in
    let src = Src.v ~doc ~tags:Tags.[] ~data "http" in
    (fun () ->
       s := succ !s;
       Metrics.add src (fun x -> x) (fun d -> d ()))

  let serve data tcp =
    incr_access ();
    S.TCP.writev tcp data >>= fun _ ->
    S.TCP.close tcp

  let serve_tls cfg data tcp_flow =
    incr_access ();
    TLS.server_of_flow cfg tcp_flow >>= function
    | Ok tls_flow ->
      TLS.writev tls_flow data >>= fun _ ->
      TLS.close tls_flow
    | Error e ->
      Logs.warn (fun m -> m "TLS error %a" TLS.pp_write_error e);
      S.TCP.close tcp_flow

  let start stack management =
    let hostname =
      let ( let* ) = Result.bind in
      match
        let* dn = Domain_name.of_string (K.host ()) in
        Domain_name.host dn
      with
      | Ok h -> h
      | Error `Msg msg ->
        Logs.err (fun m -> m "hostname %s is not a hostname: %s" (K.host ()) msg);
        exit Mirage_runtime.argument_error
    in
    let data =
      let content_size = Cstruct.length Page.rendered in
      [ header content_size ; Page.rendered ]
    in
    (if not (K.no_tls ()) then
       match K.dns_key (), K.dns_server (), K.key () with
       | None, _, _ | _, None, _ | _, _, None ->
         Logs.err (fun m -> m "TLS operations requires dns-key, dns-server, and key arguments");
         exit Mirage_runtime.argument_error
       | Some dns_key, Some dns_server, Some key ->
         let key_type, key_data, key_seed =
           match String.split_on_char ':' key with
           | [ typ ; data ] ->
             (match X509.Key_type.of_string typ with
              | Ok `RSA -> `RSA, None, Some data
              | Ok x -> x, Some data, None
              | Error `Msg msg ->
                Logs.err (fun m -> m "Error decoding key type: %s" msg);
                exit Mirage_runtime.argument_error)
           | _ ->
             Logs.err (fun m -> m "expected for key type:data");
             exit Mirage_runtime.argument_error
         in
         let additional_hostnames = K.additional_hostnames () in
         Dns_certify.retrieve_certificate
           stack dns_key ~hostname ~additional_hostnames ~key_type ?key_data
           ?key_seed dns_server (K.dns_port ()) >|= function
         | Error (`Msg msg) ->
           Logs.err (fun m -> m "error while requesting certificate: %s" msg);
           exit Mirage_runtime.argument_error
         | Ok certificates ->
           let certificates = `Single certificates in
           match Tls.Config.server ~certificates () with
           | Error `Msg msg ->
             Logs.err (fun m -> m "error while building TLS configuration: %s" msg);
             exit Mirage_runtime.argument_error
           | Ok tls_config ->
             Logs.info (fun m -> m "listening for HTTPS on port %u" (K.https_port ()));
             S.TCP.listen (S.tcp stack) ~port:(K.https_port ()) (serve_tls tls_config data)
     else
       Lwt.return_unit) >>= fun () ->
    Logs.info (fun m -> m "listening for HTTP in port %u" (K.http_port ()));
    S.TCP.listen (S.tcp stack) ~port:(K.http_port ()) (serve data) ;
    S.listen stack
end
