//! Opt-in warm-path comparison with the Go channel benchmark peer.
//! The peer's local CA and synthetic evidence are test fixtures; these timings
//! exclude hardware attestation, approval verification, JSON parsing and inference.

use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::stream;
use http_body_util::{BodyExt as _, Full, StreamBody, combinators::BoxBody};
use hyper::{
    Request,
    body::{Bytes, Frame},
    client::conn::http2::SendRequest,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant as WallClock,
};
use stogas_verifier::{
    approvals::Environment,
    channel::{ClientSession, Kind, MAX_RECORD_PLAINTEXT, ResponseDecoder, setup::PendingSetup},
};
use tokio::{net::TcpStream, task::JoinHandle};
use tokio_rustls::TlsConnector;

type Body = BoxBody<Bytes, Infallible>;
type Sender = SendRequest<Body>;

struct BenchmarkIo {
    stream: TrafficStream<TcpStream>,
    update: Arc<AtomicBool>,
}

impl AsyncRead for BenchmarkIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, out)
    }
}
impl AsyncWrite for BenchmarkIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !data.is_empty() && self.update.swap(false, Ordering::Relaxed) {
            self.stream.updated_at = Instant::now() - KEY_UPDATE_INTERVAL;
        }
        Pin::new(&mut self.stream).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if bufs.iter().any(|buf| !buf.is_empty()) && self.update.swap(false, Ordering::Relaxed) {
            self.stream.updated_at = Instant::now() - KEY_UPDATE_INTERVAL;
        }
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }
}

async fn connect(config: &Value, chacha: bool) -> (Sender, JoinHandle<()>, Arc<AtomicBool>) {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            STANDARD
                .decode(config["certificate"].as_str().unwrap())
                .unwrap(),
        ))
        .unwrap();
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = vec![if chacha {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
    } else {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384
    }];
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    client.resumption = rustls::client::Resumption::disabled();
    client.enable_early_data = false;
    let socket = TcpStream::connect(config["address"].as_str().unwrap())
        .await
        .unwrap();
    socket.set_nodelay(true).unwrap();
    let stream = TlsConnector::from(Arc::new(client))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            socket,
        )
        .await
        .unwrap();
    assert_eq!(
        stream.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        stream
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .unwrap()
            .name(),
        rustls::NamedGroup::X25519MLKEM768
    );
    let update = Arc::new(AtomicBool::new(false));
    let io = BenchmarkIo {
        stream: TrafficStream::new(stream),
        update: Arc::clone(&update),
    };
    let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .initial_stream_window_size(1 << 20)
        .initial_connection_window_size(1 << 20)
        .max_frame_size(1 << 20)
        .handshake(TokioIo::new(io))
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        connection.await.unwrap();
    });
    (sender, task, update)
}

async fn session(sender: &mut Sender) -> ClientSession {
    let mut pending = PendingSetup::new(Environment::Production).unwrap();
    let request = Request::post("https://localhost/setup")
        .body(Full::new(Bytes::copy_from_slice(pending.hello())).boxed())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert!(response.status().is_success());
    let encoded = response.into_body().collect().await.unwrap().to_bytes();
    // The benchmark peer returns synthetic evidence. No production verifier
    // configuration or application entry point supports this test-only policy.
    pending.complete(&encoded, |_| Ok(())).unwrap()
}

#[derive(Clone)]
struct Case {
    name: String,
    body: Bytes,
    response: usize,
    chunk: usize,
    flush: bool,
    concurrency: usize,
}

fn request_body(
    data: Bytes,
    session: Option<Arc<Mutex<ClientSession>>>,
) -> (Body, Option<ResponseDecoder>) {
    let mut decoder = None;
    let body: Body = if let Some(session) = session {
        let request = session.lock().unwrap().request().unwrap();
        let (writer, reader) = request.split();
        decoder = Some(reader);
        let chunks = stream::unfold(
            (writer, data, 0_usize, 0_u8),
            |(mut writer, data, position, stage)| async move {
                let (bytes, position, next) = match stage {
                    0 => (Bytes::copy_from_slice(&writer.prefix()), position, 1),
                    1 => (
                        Bytes::from(
                            writer
                                .seal(
                                    Kind::Metadata,
                                    br#"{"method":"POST","path":"/upload","headers":{}}"#,
                                )
                                .unwrap(),
                        ),
                        position,
                        2,
                    ),
                    2 if position < data.len() => {
                        let end = (position + MAX_RECORD_PLAINTEXT).min(data.len());
                        (
                            Bytes::from(writer.seal(Kind::Data, &data[position..end]).unwrap()),
                            end,
                            2,
                        )
                    }
                    2 => (
                        Bytes::from(writer.seal(Kind::Finished, &[]).unwrap()),
                        position,
                        3,
                    ),
                    _ => return None,
                };
                Some((
                    Ok::<_, Infallible>(Frame::data(bytes)),
                    (writer, data, position, next),
                ))
            },
        );
        StreamBody::new(chunks).boxed()
    } else {
        let chunks = stream::unfold((data, 0), |(data, position)| async move {
            if position == data.len() {
                return None;
            }
            let end = (position + MAX_RECORD_PLAINTEXT).min(data.len());
            Some((
                Ok::<_, Infallible>(Frame::data(data.slice(position..end))),
                (data, end),
            ))
        });
        StreamBody::new(chunks).boxed()
    };
    (body, decoder)
}

async fn exchange(
    mut sender: Sender,
    session: Option<Arc<Mutex<ClientSession>>>,
    case: Case,
    update: Arc<AtomicBool>,
    force_update: bool,
) -> (f64, f64) {
    let began = WallClock::now();
    let encrypted = session.is_some();
    let (body, mut decoder) = request_body(case.body.clone(), session);
    let request = Request::post(if encrypted {
        "https://localhost/e2ee"
    } else {
        "https://localhost/tls"
    })
    .header("x-response-bytes", case.response.to_string())
    .header("x-response-chunk", case.chunk.to_string())
    .header("x-flush", if case.flush { "1" } else { "0" })
    .body(body)
    .unwrap();
    if force_update {
        update.store(true, Ordering::Relaxed);
    }
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.version(), hyper::Version::HTTP_2);
    assert!(
        response.status().is_success(),
        "benchmark response {}",
        response.status()
    );
    assert_eq!(
        response.headers()["x-received-bytes"]
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        case.body.len()
    );
    let mut incoming = response.into_body();
    let mut received = 0;
    let mut first = None;
    while let Some(frame) = incoming.frame().await {
        let frame = frame.unwrap();
        if let Ok(bytes) = frame.into_data() {
            if let Some(reader) = &mut decoder {
                reader
                    .push(&bytes, 0, |kind, content| {
                        if kind == Kind::Data {
                            received += content.len();
                            first.get_or_insert_with(|| began.elapsed().as_secs_f64());
                        }
                        Ok(())
                    })
                    .unwrap();
            } else {
                received += bytes.len();
                first.get_or_insert_with(|| began.elapsed().as_secs_f64());
            }
        }
    }
    if let Some(reader) = decoder {
        reader.finish().unwrap();
    }
    assert_eq!(received, case.response);
    (began.elapsed().as_secs_f64(), first.unwrap())
}

fn process_stats() -> Value {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    let ticks = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
    let ticks_per_second: f64 = std::env::var("STOGAS_BENCH_CLK_TCK")
        .unwrap()
        .parse()
        .unwrap();
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let kib = |name: &str| {
        status
            .lines()
            .find(|line| line.starts_with(name))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    json!({"cpu_seconds": f64::from(u32::try_from(ticks).unwrap())/ticks_per_second, "rss_kib": kib("VmRSS:"), "peak_rss_kib": kib("VmHWM:")})
}

fn percentile(values: &mut [f64], percent: usize) -> f64 {
    values.sort_by(f64::total_cmp);
    values[(values.len() * percent).div_ceil(100).saturating_sub(1)] * 1000.0
}

fn cases(large: Bytes) -> Vec<Case> {
    let mut cases = Vec::new();
    for (name, body) in [
        ("4KiB", Bytes::from(vec![b'a'; 4096])),
        ("64KiB", Bytes::from(vec![b'a'; 64 << 10])),
        ("1MiB", Bytes::from(vec![b'a'; 1 << 20])),
        ("3M_tokens", large),
        ("96MiB", Bytes::from(vec![b'a'; 96 << 20])),
    ] {
        for concurrency in [1, 8] {
            if name == "96MiB" && concurrency != 1 {
                continue;
            }
            cases.push(Case {
                name: name.into(),
                body: body.clone(),
                response: 4096,
                chunk: 4096,
                flush: false,
                concurrency,
            });
        }
    }
    for concurrency in [1, 8] {
        cases.push(Case {
            name: "stream_256B".into(),
            body: Bytes::from(vec![b'a'; 4096]),
            response: 128 << 10,
            chunk: 256,
            flush: true,
            concurrency,
        });
    }
    cases
}

async fn sample(
    sender: &Sender,
    session: Option<&Arc<Mutex<ClientSession>>>,
    case: &Case,
    update: &Arc<AtomicBool>,
    force_update: bool,
    seconds: f64,
) -> (f64, Vec<f64>, Vec<f64>) {
    let begin = WallClock::now();
    let mut timings = Vec::new();
    let mut firsts = Vec::new();
    let minimum =
        std::env::var("STOGAS_BENCH_MIN_SAMPLES").map_or(16, |s| s.parse::<usize>().unwrap());
    assert!(minimum > 0);
    while begin.elapsed().as_secs_f64() < seconds || timings.len() < minimum {
        let futures = (0..case.concurrency).map(|_| {
            exchange(
                sender.clone(),
                session.cloned(),
                case.clone(),
                update.clone(),
                force_update,
            )
        });
        for (elapsed, first) in futures_util::future::join_all(futures).await {
            timings.push(elapsed);
            firsts.push(first);
        }
    }
    (begin.elapsed().as_secs_f64(), timings, firsts)
}

fn configuration() -> (Value, String, f64, usize, Vec<Case>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("STOGAS_TRANSPORT_BENCH_CONFIG").unwrap()).unwrap(),
    )
    .unwrap();
    assert!(
        config["address"]
            .as_str()
            .unwrap()
            .starts_with("127.0.0.1:")
    );
    assert!(
        config["admin"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:")
    );
    let output = std::env::var("STOGAS_TRANSPORT_BENCH_OUTPUT").unwrap();
    let seconds: f64 = std::env::var("STOGAS_BENCH_SECONDS")
        .unwrap_or_else(|_| "2".into())
        .parse()
        .unwrap();
    let rounds: usize = std::env::var("STOGAS_BENCH_ROUNDS")
        .unwrap_or_else(|_| "3".into())
        .parse()
        .unwrap();
    let large = Bytes::from(std::fs::read(std::env::var("STOGAS_BENCH_PAYLOAD").unwrap()).unwrap());
    let cases = cases(large);
    (config, output, seconds, rounds, cases)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an explicit loopback Go benchmark peer and result path"]
#[allow(
    clippy::too_many_lines,
    reason = "Keep benchmark modes and their shared measurement scope together."
)]
async fn warm_transport_comparison() {
    let (config, output, seconds, rounds, cases) = configuration();
    let admin = config["admin"].as_str().unwrap();
    let admin_client = reqwest::Client::builder().no_proxy().build().unwrap();
    let modes = [
        "tls",
        "e2ee",
        "tls_update_each_request",
        "tls_chacha",
        "e2ee_chacha",
        "e2ee_extra_128",
        "e2ee_extra_256",
        "e2ee_extra_512",
        "e2ee_extra_1168",
        "e2ee_extra_1408",
    ];
    let selected = std::env::var("STOGAS_BENCH_MODES").unwrap_or_else(|_| "tls,e2ee".into());
    let case_filter = std::env::var("STOGAS_BENCH_CASES").unwrap_or_default();
    let mut rows = Vec::new();
    for round in 0..rounds {
        for case in &cases {
            if !case_filter.is_empty() && !case_filter.split(',').any(|name| name == case.name) {
                continue;
            }
            let selected_modes: Vec<_> = modes
                .iter()
                .filter(|mode| selected.split(',').any(|name| name == **mode))
                .collect();
            for order in 0..selected_modes.len() {
                let mode = *selected_modes[(order + round) % selected_modes.len()];
                let concurrency_filter =
                    std::env::var("STOGAS_BENCH_CONCURRENCY").unwrap_or_default();
                if !concurrency_filter.is_empty()
                    && !concurrency_filter
                        .split(',')
                        .any(|v| v.parse::<usize>().unwrap() == case.concurrency)
                {
                    continue;
                }
                // Extra-byte variants measure transport cost only. They do not
                // claim to execute or validate an integrated recovery protocol.
                let extra = mode
                    .strip_prefix("e2ee_extra_")
                    .map_or(0, |s| s.parse::<usize>().unwrap());
                let mut padded = case.clone();
                if extra > 0 {
                    let mut body = padded.body.to_vec();
                    body.resize(body.len() + extra, 0);
                    padded.body = body.into();
                    padded.response += extra;
                }
                let case = &padded;
                admin_client
                    .post(format!("{admin}/reset"))
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap();
                let (mut sender, task, update) = connect(&config, mode.ends_with("chacha")).await;
                let session = if mode.starts_with("e2ee") {
                    Some(Arc::new(Mutex::new(session(&mut sender).await)))
                } else {
                    None
                };
                exchange(
                    sender.clone(),
                    session.clone(),
                    case.clone(),
                    update.clone(),
                    false,
                )
                .await;
                let _ = std::fs::write("/proc/self/clear_refs", "5");
                let before: Value = admin_client
                    .get(format!("{admin}/metrics"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                let client_before = process_stats();
                let (wall, mut timings, mut firsts) = sample(
                    &sender,
                    session.as_ref(),
                    case,
                    &update,
                    mode == "tls_update_each_request",
                    seconds,
                )
                .await;
                let client_after = process_stats();
                let after: Value = admin_client
                    .get(format!("{admin}/metrics"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                assert_eq!(after["errors"], before["errors"]);
                let number = f64::from(u32::try_from(timings.len()).unwrap());
                let delta =
                    |field: &str| after[field].as_f64().unwrap() - before[field].as_f64().unwrap();
                let row = json!({"round":round,"mode":mode,"case":case.name,"request_bytes":case.body.len(),"response_bytes":case.response,"concurrency":case.concurrency,"requests":timings.len(),"wall_seconds":wall,"p50_ms":percentile(&mut timings,50),"p95_ms":percentile(&mut timings,95),"first_response_p50_ms":percentile(&mut firsts,50),"client_cpu_ms_per_request":(client_after["cpu_seconds"].as_f64().unwrap()-client_before["cpu_seconds"].as_f64().unwrap())*1000.0/number,"server_cpu_ms_per_request":delta("cpu_seconds")*1000.0/number,"upload_wire_bytes_per_request":delta("read_wire_bytes")/number,"download_wire_bytes_per_request":delta("written_wire_bytes")/number,"server_allocated_bytes_per_request":delta("allocated_bytes")/number,"server_gc_cycles":delta("gc_count"),"client_rss_before_kib":client_before["rss_kib"],"client_peak_rss_kib":client_after["peak_rss_kib"],"server_rss_before_kib":before["rss_kib"],"server_peak_rss_kib":after["peak_rss_kib"],"latencies_ms":timings.iter().map(|s| s*1000.0).collect::<Vec<_>>()});
                eprintln!(
                    "{} {} c{} round{}: {:.3} ms",
                    mode,
                    case.name,
                    case.concurrency,
                    round,
                    row["p50_ms"].as_f64().unwrap()
                );
                rows.push(row);
                std::fs::write(&output, serde_json::to_vec_pretty(&json!({"scope":"warm Rust client to Go server on loopback; real TLS13 hybrid/AES256 or ChaCha, HTTP2, production E2EE records and ratchet; synthetic setup evidence; no inference/JSON/authorization/SDK proxy/WAN/SNP; wire bytes exclude TCP/IP; client CPU uses process clock ticks","server":config["go_version"],"server_cpus":config["gomaxprocs"],"client_threads":4,"rows":rows})).unwrap()).unwrap();
                drop(sender);
                drop(session);
                task.abort();
                let _ = task.await;
            }
        }
    }
}

// A recovery building block, not a complete double-ratchet protocol. Every
// iteration generates a fresh X-Wing recipient and executes both endpoints,
// checks exported secret agreement, and mixes the contribution into both roots.
#[test]
#[ignore = "explicit CPU microbenchmark; no network or production protocol change"]
fn hybrid_recovery_cost() {
    use aws_lc_rs::hkdf;
    use hpke::{
        Kem as _, OpModeR, OpModeS, Serializable as _, aead::ExportOnlyAead, kdf::HkdfSha256,
        kem::XWing, setup_receiver, setup_sender,
    };
    struct RootMaterial;
    impl hkdf::KeyType for RootMaterial {
        fn len(&self) -> usize {
            64
        }
    }
    let mix = |root: &[u8; 32], secret: &[u8; 32]| {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, root);
        let prk = salt.extract(secret);
        let mut result = zeroize::Zeroizing::new([0_u8; 64]);
        prk.expand(&[b"benchmark recovery root"], RootMaterial)
            .unwrap()
            .fill(result.as_mut())
            .unwrap();
        result
    };
    let mut root = zeroize::Zeroizing::new([1_u8; 32]);
    let mut rows = Vec::new();
    for round in 0..5 {
        let before = process_stats();
        let started = WallClock::now();
        let mut count = 0_u32;
        let mut wire = 0;
        while started.elapsed() < Duration::from_secs(1) {
            let (private, public) = XWing::gen_keypair();
            let (enc, sender) = setup_sender::<ExportOnlyAead, HkdfSha256, XWing>(
                &OpModeS::Base,
                &public,
                b"benchmark recovery",
            )
            .unwrap();
            let receiver = setup_receiver::<ExportOnlyAead, HkdfSha256, XWing>(
                &OpModeR::Base,
                &private,
                &enc,
                b"benchmark recovery",
            )
            .unwrap();
            let mut left = zeroize::Zeroizing::new([0_u8; 32]);
            let mut right = zeroize::Zeroizing::new([0_u8; 32]);
            sender.export(b"root contribution", left.as_mut()).unwrap();
            receiver
                .export(b"root contribution", right.as_mut())
                .unwrap();
            assert_eq!(left, right);
            let next = mix(&root, &left);
            let other = mix(&root, &right);
            assert_eq!(next, other);
            root.copy_from_slice(&next[..32]);
            std::hint::black_box(&root);
            wire = public.to_bytes().len() + enc.to_bytes().len();
            count += 1;
        }
        let elapsed = started.elapsed().as_secs_f64();
        let after = process_stats();
        rows.push(json!({"round":round,"iterations":count,"nanoseconds_per_exchange":elapsed*1e9/f64::from(count),"cpu_ns_per_exchange":(after["cpu_seconds"].as_f64().unwrap()-before["cpu_seconds"].as_f64().unwrap())*1e9/f64::from(count),"crypto_wire_bytes":wire}));
    }
    std::fs::write(std::env::var("STOGAS_RECOVERY_BENCH_OUTPUT").unwrap(), serde_json::to_vec_pretty(&json!({"scope":"Rust hpke 0.14 X-Wing fresh recipient + encapsulation + decapsulation + exports + two root mix operations; not a full PQ ratchet","rows":rows})).unwrap()).unwrap();
}
