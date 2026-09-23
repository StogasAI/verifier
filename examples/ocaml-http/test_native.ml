let connect port =
  let socket = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Fun.protect ~finally:(fun () -> Unix.close socket) (fun () ->
    Unix.connect socket (Unix.ADDR_INET (Unix.inet_addr_loopback, port)))

exception Interrupted

let () =
  let library = Sys.argv.(1) in
  List.iter (fun interrupted ->
    let port = ref 0 in
    (try Transport.with_transport library
      (`Assoc ["environment", `String "staging";
               "security", `String (if interrupted then "e2ee" else "tls")]) (fun url ->
        port := Option.get (Uri.port (Uri.of_string url));
        connect !port;
        if interrupted then raise Interrupted)
     with Interrupted -> ());
    match connect !port with
    | () -> failwith "Native listener survived close"
    | exception Unix.Unix_error (Unix.ECONNREFUSED, _, _) -> ()) [false; true];
  (match Transport.with_transport library (`Assoc ["security", `String "unknown"]) (fun _ -> ()) with
   | () -> failwith "Invalid configuration accepted"
   | exception Failure _ -> ());
  print_endline "Native ownership and exception cleanup passed"
