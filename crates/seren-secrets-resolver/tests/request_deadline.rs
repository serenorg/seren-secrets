//! Production-default regression: a metered error that arrives after 31 seconds
//! must still be reported with its status.

use seren_secrets_resolver::{ResolverError, list_agents};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct ServerTask(tokio::task::JoinHandle<()>);
impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
#[ignore = "waits 31 seconds; run with --ignored"]
async fn production_default_preserves_metered_408_after_old_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (received, request_seen) = tokio::sync::oneshot::channel();
    let mut server = ServerTask(tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut chunk = [0; 4096];
            let n = socket.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0);
            bytes.extend_from_slice(&chunk[..n]);
            assert!(bytes.len() < 16384);
        }
        received.send(()).unwrap();
        tokio::time::sleep(Duration::from_secs(31)).await;
        let body =
            r#"{"data":{"status":408,"body":{"error":{"message":"synthetic upstream timeout"}}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
    }));
    let start = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(40), async {
        let (result, seen) = tokio::join!(list_agents(&url, "synthetic-bearer"), request_seen);
        seen.unwrap();
        result
    })
    .await
    .expect("production call exceeded regression guard");
    let elapsed = start.elapsed();
    let error = result.expect_err("expected upstream error");
    assert!(
        matches!(error, ResolverError::ServerError { status: 408, .. }),
        "expected upstream 408, got {error:?} after {elapsed:?}"
    );
    assert!(elapsed >= Duration::from_secs(31));
    (&mut server.0).await.unwrap();
}
