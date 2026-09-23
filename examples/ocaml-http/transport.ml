open Ctypes

let with_transport library configuration action =
  let native = Dl.dlopen ~filename:library ~flags:[Dl.RTLD_NOW; Dl.RTLD_LOCAL] in
  let bind name signature = Foreign.foreign ~from:native name signature in
  let abi = bind "stogas_verifier_abi_version" (void @-> returning uint32_t) in
  let start = bind "stogas_transport_start"
    (string @-> size_t @-> ptr (ptr void) @-> returning (ptr char)) in
  let close = bind "stogas_transport_close" (ptr void @-> returning void) in
  let free = bind "stogas_transport_free" (ptr void @-> returning void) in
  let free_string = bind "stogas_verifier_string_free" (ptr char @-> returning void) in
  if Unsigned.UInt32.to_int (abi ()) <> 1 then failwith "Unsupported verifier ABI";
  let bytes = Yojson.Safe.to_string configuration in
  let output = allocate (ptr void) null in
  let raw = start bytes (Unsigned.Size_t.of_int (String.length bytes)) output in
  Fun.protect ~finally:(fun () -> close !@output; free !@output) (fun () ->
    let result = Fun.protect ~finally:(fun () -> free_string raw) (fun () ->
      if is_null raw then failwith "Unable to start verified transport";
      Yojson.Safe.from_string (coerce (ptr char) string raw)) in
    let open Yojson.Safe.Util in
    if is_null !@output || member "ok" result <> `Bool true then
      failwith "Unable to start verified transport";
    let url = result |> member "value" |> member "base_url" |> to_string in
    action url)
