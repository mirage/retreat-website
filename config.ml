(* mirage >= 4.8.0 & < 4.9.0 *)
open Mirage

(* uTCP *)

let tcpv4v6_direct_conf id =
  let packages_v = Key.pure [ package "utcp" ~sublibs:[ "mirage" ] ] in
  let connect _ modname = function
    | [_random; _mclock; _time; ip] ->
      code ~pos:__POS__ "Lwt.return (%s.connect %S %s)" modname id ip
    | _ -> failwith "direct tcpv4v6"
  in
  impl ~packages_v ~connect "Utcp_mirage.Make"
    (random @-> mclock @-> time @-> ipv4v6 @-> (tcp: 'a tcp typ))

let direct_tcpv4v6
    ?(clock=default_monotonic_clock)
    ?(random=default_random)
    ?(time=default_time) id ip =
  tcpv4v6_direct_conf id $ random $ clock $ time $ ip

let net ?group name netif =
  let ethernet = ethif netif in
  let arp = arp ethernet in
  let i4 = create_ipv4 ?group ethernet arp in
  let i6 = create_ipv6 ?group netif ethernet in
  let i4i6 = create_ipv4v6 ?group i4 i6 in
  let tcpv4v6 = direct_tcpv4v6 name i4i6 in
  direct_stackv4v6 ?group ~tcp:tcpv4v6 netif ethernet arp i4 i6

let net = net "service" default_network

let enable_monitoring =
  let doc = Key.Arg.info
      ~doc:"Enable monitoring (syslog, metrics to influx, log level, statmemprof tracing)"
      [ "enable-monitoring" ]
  in
  Key.(create "enable-monitoring" Arg.(flag doc))

let management_stack =
  if_impl
    (Key.value enable_monitoring)
    (generic_stackv4v6 ~group:"management"
       (netif ~group:"management" "management"))
    net

let name = runtime_arg ~pos:__POS__ "Unikernel.K.hostname"

let monitoring =
  let monitor = Runtime_arg.(v (monitor None)) in
  let connect _ modname = function
    | [ _ ; _ ; stack ; name ; monitor ] ->
      code ~pos:__POS__
        "Lwt.return (match %s with\
         | None -> Logs.warn (fun m -> m \"no monitor specified, not outputting statistics\")\
         | Some ip -> %s.create ip ~hostname:(Domain_name.to_string %s) %s)"
        monitor modname name stack
    | _ -> assert false
  in
  impl
    ~packages:[ package "mirage-monitoring" ]
    ~runtime_args:[ name; monitor ]
    ~connect "Mirage_monitoring.Make"
    (time @-> pclock @-> stackv4v6 @-> job)

let syslog =
  let syslog = Runtime_arg.(v (syslog None)) in
  let connect _ modname = function
    | [ _ ; stack ; name ; syslog ] ->
      code ~pos:__POS__
        "Lwt.return (match %s with\
         | None -> Logs.warn (fun m -> m \"no syslog specified, dumping on stdout\")\
         | Some ip -> Logs.set_reporter (%s.create %s ip ~hostname:(Domain_name.to_string %s) ()))"
        syslog modname stack name
    | _ -> assert false
  in
  impl
    ~packages:[ package ~sublibs:[ "mirage" ] ~min:"0.4.0" "logs-syslog" ]
    ~runtime_args:[ name; syslog ]
    ~connect "Logs_syslog_mirage.Udp"
    (pclock @-> stackv4v6 @-> job)

let optional_monitoring time pclock stack =
  if_impl
    (Key.value enable_monitoring)
    (monitoring $ time $ pclock $ stack)
    noop

let optional_syslog pclock stack =
  if_impl (Key.value enable_monitoring) (syslog $ pclock $ stack) noop

let packages = [
  package "logs" ;
  package "cmarkit" ;
  package ~min:"3.7.1" "tcpip" ;
  package ~min:"6.1.1" ~sublibs:["mirage"] "dns-certify";
  package "tls-mirage";
  package ~min:"4.5.0" ~sublibs:["network"] "mirage-runtime";
  package ~pin:"git+https://github.com/robur-coop/utcp.git" "utcp";
]

let () =
  register "retreat" [
    optional_syslog default_posix_clock management_stack;
    optional_monitoring default_time default_posix_clock management_stack;

    main
      ~packages
      "Unikernel.Main"
    (random @-> time @-> pclock @-> stackv4v6 @-> stackv4v6 @-> job)
    $ default_random $ default_time $ default_posix_clock $ net $ management_stack
  ]
