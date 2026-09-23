#![cfg(all(unix, feature = "staging"))]

use std::{
    io::{BufRead, BufReader},
    net::TcpStream,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn proxy_process_closes_cleanly_on_signals_and_parent_pipe_loss() {
    for trigger in ["-INT", "-TERM", "stdin", "-TERM-with-stdin"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stogas-verify"));
        command
            .args([
                "serve",
                "--environment",
                "staging",
                "--listen",
                "127.0.0.1:0",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if trigger.contains("stdin") {
            command.arg("--exit-on-stdin-close");
        }
        let mut child = Process(command.spawn().unwrap());
        let stdout = child.0.stdout.take().unwrap();
        let (sent, received) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut lines = BufReader::new(stdout).lines();
            sent.send((lines.next(), lines.next())).unwrap();
        });
        // Like the native ownership qualification, this verifies current staging
        // evidence during startup. It sends no inference or customer credentials.
        let (base, refresh) = received.recv_timeout(Duration::from_secs(20)).unwrap();
        reader.join().unwrap();
        let base = base.unwrap().unwrap();
        assert!(
            refresh
                .unwrap()
                .unwrap()
                .starts_with("Evidence refresh URL: http://127.0.0.1:")
        );
        let url = url::Url::parse(base.strip_prefix("OpenAI base URL: ").unwrap()).unwrap();
        let address = format!("127.0.0.1:{}", url.port().unwrap());
        // Leave a connection awaiting HTTP headers: close remains bounded.
        let idle = TcpStream::connect(&address).unwrap();
        if trigger == "stdin" {
            drop(child.0.stdin.take());
        } else {
            let signal = if trigger == "-INT" { "-INT" } else { "-TERM" };
            assert!(
                Command::new("kill")
                    .args([signal, &child.0.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let deadline = Instant::now() + Duration::from_secs(7);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "proxy failed to close within its budget"
            );
            thread::sleep(Duration::from_millis(20));
        };
        assert!(
            status.success(),
            "proxy did not finish gracefully: {status}"
        );
        drop(idle);
        assert!(
            TcpStream::connect(&address).is_err(),
            "proxy listener survived shutdown"
        );
    }
}
