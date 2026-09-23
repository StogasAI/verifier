open Yojson.Safe.Util

let decode text =
  match Yojson.Safe.from_string text with
  | `Assoc fields as value when not (List.mem_assoc "error" fields) -> value
  | _ -> failwith "Invalid response or stream error"

let content field value =
  match member "choices" value with
  | `List choices -> List.iter (fun choice ->
      match choice |> member field |> member "content" with
      | `String text -> print_string text; flush stdout
      | _ -> ()) choices
  | _ -> ()

type sse = {
  line: Buffer.t; data: Buffer.t; mutable size: int;
  mutable has_data: bool; mutable done_: bool; mutable skip_lf: bool;
}

let feed state chunk =
  String.iter (fun byte ->
    if byte = '\n' && state.skip_lf then state.skip_lf <- false
    else begin
      state.skip_lf <- byte = '\r';
      if byte <> '\n' && byte <> '\r' then begin
        state.size <- state.size + 1;
        if state.size > 8 * 1024 * 1024 then failwith "Stream event too large";
        Buffer.add_char state.line byte
      end else begin
        let line = Buffer.contents state.line in
        Buffer.clear state.line;
        if line = "" then begin
          if state.has_data then begin
            if state.done_ then failwith "Data after completion";
            let payload = Buffer.contents state.data in
            if payload = "[DONE]" then state.done_ <- true
            else content "delta" (decode payload)
          end;
          Buffer.clear state.data;
          state.has_data <- false;
          state.size <- 0
        end else begin
          let name, value = match String.index_opt line ':' with
            | None -> line, ""
            | Some i -> String.sub line 0 i, String.sub line (i + 1) (String.length line - i - 1) in
          if name = "data" then begin
            let value = if String.starts_with ~prefix:" " value then
              String.sub value 1 (String.length value - 1) else value in
            if state.has_data then Buffer.add_char state.data '\n';
            Buffer.add_string state.data value;
            state.has_data <- true
          end
        end
      end
    end) chunk

let request base =
  let streaming = match Array.to_list Sys.argv with
    | [_] -> true | [_; "--no-stream"] -> false | _ -> failwith "Unsupported arguments" in
  let key = Sys.getenv "STOGAS_API_KEY" and model = Sys.getenv "STOGAS_MODEL" in
  if key = "" || model = "" || String.contains key '\r' || String.contains key '\n' then
    failwith "Missing request settings";
  let uri = Uri.of_string base in
  if Uri.scheme uri <> Some "http" || Uri.host uri <> Some "127.0.0.1" || Uri.userinfo uri <> None then
    failwith "Expected the private loopback URL";
  let cancelled = ref false in
  let previous = Sys.signal Sys.sigint (Sys.Signal_handle (fun _ -> cancelled := true)) in
  let curl = Curl.init () in
  Fun.protect ~finally:(fun () -> Curl.cleanup curl; Sys.set_signal Sys.sigint previous) (fun () ->
    Curl.set_url curl (base ^ "/chat/completions");
    Curl.set_proxy curl "";
    Curl.set_followlocation curl false;
    Curl.set_connecttimeout curl 15;
    Curl.set_timeout curl (45 * 60);
    Curl.set_noprogress curl false;
    Curl.set_progressfunction curl (fun _ _ _ _ -> !cancelled);
    Curl.set_httpheader curl ["Authorization: Bearer " ^ key; "Content-Type: application/json"];
    Curl.set_postfields curl (Yojson.Safe.to_string (`Assoc [
      "model", `String model; "stream", `Bool streaming;
      "messages", `List [`Assoc ["role", `String "user"; "content", `String "Say hello in one sentence."]]]));
    let state = {line = Buffer.create 256; data = Buffer.create 256; size = 0;
                 has_data = false; done_ = false; skip_lf = false} in
    let body = Buffer.create 1024 in
    Curl.set_writefunction curl (fun chunk ->
      try
        if !cancelled || Curl.get_responsecode curl <> 200 then 0
        else begin
          if streaming then feed state chunk
          else begin
            if Buffer.length body + String.length chunk > 32 * 1024 * 1024 then
              failwith "Response too large";
            Buffer.add_string body chunk
          end;
          String.length chunk
        end
      with _ -> 0);
    Curl.perform curl;
    if !cancelled || Curl.get_responsecode curl <> 200 then failwith "Request failed";
    if streaming then begin
      if not state.done_ || state.has_data || Buffer.length state.line <> 0 then
        failwith "Incomplete stream"
    end else content "message" (decode (Buffer.contents body));
    print_newline ())

let () =
  Curl.global_init Curl.CURLINIT_GLOBALALL;
  try
    Fun.protect ~finally:Curl.global_cleanup (fun () ->
      match Sys.getenv_opt "STOGAS_BASE_URL" with
      | Some url -> request url
      | None -> Transport.with_transport (Sys.getenv "STOGAS_VERIFIER_LIB") (`Assoc []) request)
  with _ ->
    prerr_endline "Request failed or incomplete. Do not replay automatically.";
    exit 1
