use super::*;
use axum::{Router, body::Body, http::Response, routing::post};
use futures_util::stream;
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/capability/v1", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (base, task)
}

fn request() -> async_openai::types::chat::CreateChatCompletionRequest {
    CreateChatCompletionRequestArgs::default()
        .model("example/model")
        .messages([ChatCompletionRequestUserMessageArgs::default()
            .content("hello")
            .build()
            .unwrap()
            .into()])
        .build()
        .unwrap()
}

#[tokio::test]
async fn typed_request_uses_transport_path_and_never_retries_errors_or_redirects() {
    for status in [200, 307, 429, 503] {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let app = Router::new().route("/capability/v1/chat/completions", post(move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<serde_json::Value>| {
            seen.fetch_add(1, Ordering::SeqCst);
            async move {
                assert_eq!(headers["authorization"], "Bearer example-key");
                assert_eq!(body["model"], "example/model");
                assert_eq!(body["messages"][0]["content"], "hello");
                Response::builder().status(status)
                    .header("content-type", "application/json")
                    .header("location", "/capability/v1/chat/completions")
                    .body(Body::from(if status == 200 {
                        json!({"id":"chat-1", "object":"chat.completion", "created":1, "model":"example/model", "choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}]}).to_string()
                    } else { json!({"error":{"message":"unavailable", "type":"server_error"}}).to_string() })).unwrap()
            }
        }));
        let (base, task) = serve(app).await;
        let client = client(&base, "example-key").unwrap();
        let result = timeout(Duration::from_secs(2), client.chat().create(request()))
            .await
            .unwrap();
        assert_eq!(result.is_ok(), status == 200);
        if let Ok(response) = result {
            assert_eq!(
                response.choices[0].message.content.as_deref(),
                Some("Hello")
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        task.abort();
    }
}

#[tokio::test]
async fn sdk_completion_waits_for_transport_authentication_and_propagates_failure() {
    for valid in [true, false] {
        let (finish, finished) = oneshot::channel::<bool>();
        let source = Arc::new(std::sync::Mutex::new(Some(finished)));
        let app = Router::new().route("/capability/v1/chat/completions", post(move || {
            let finished = source.lock().unwrap().take().unwrap();
            async move {
                let event = json!({"id":"chat-1","object":"chat.completion.chunk","created":1,"model":"example/model","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]});
                let mut completion = stogas_verifier::receipt::StreamCompletion::default();
                let prefix = completion.push(format!(": STOGAS PROCESSING\n\ndata: {event}\n\ndata: [DONE]\n\n").as_bytes()).unwrap();
                let body = stream::iter(prefix.into_iter().map(Ok::<_, std::io::Error>))
                    .chain(stream::once(async move {
                        if finished.await.unwrap() {
                            completion.finish().unwrap();
                            Ok(b"\n\n".to_vec())
                        } else { Err(std::io::Error::other("authenticated completion failed")) }
                    }));
                Response::builder().header("content-type", "text/event-stream")
                    .body(Body::from_stream(body)).unwrap()
            }
        }));
        let (base, task) = serve(app).await;
        let client = client(&base, "example-key").unwrap();
        let mut stream = client.chat().create_stream(request()).await.unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap().choices[0]
                .delta
                .content
                .as_deref(),
            Some("Hello")
        );
        assert!(
            timeout(Duration::from_millis(30), stream.next())
                .await
                .is_err()
        );
        finish.send(valid).unwrap();
        let terminal = timeout(Duration::from_secs(2), stream.next())
            .await
            .unwrap();
        if valid {
            assert!(terminal.is_none());
        } else {
            assert!(terminal.unwrap().is_err());
        }
        task.abort();
    }
}
