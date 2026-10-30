//! Loopback-only HTTP fixture. Captured synthetic secrets are never formatted.

use crate::{TransportErrorKind, error::ResolverError};
use std::error::Error;
use std::future::Future;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

pub const BEARER: &str = "synthetic-bearer-sentinel";
pub const SENSITIVE: &str = "synthetic-sensitive-sentinel";
pub const BUDGET: Duration = Duration::from_millis(300);

pub async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("loopback operation exceeded test guard")
}

/// A classified client timeout that keeps its HTTP source and formats neither
/// the bearer, the base-URL path, nor the peer address.
pub fn assert_timeout(error: &ResolverError) {
    let ResolverError::Transport(transport) = error else {
        panic!("expected a transport timeout");
    };
    assert_eq!(transport.kind(), TransportErrorKind::Timeout);
    assert!(error.to_string().contains("timed out"));
    let mut source = error.source();
    let mut from_client = false;
    while let Some(err) = source {
        from_client |= err.downcast_ref::<reqwest::Error>().is_some();
        source = err.source();
    }
    assert!(from_client);
    for text in [error.to_string(), format!("{error:?}")] {
        assert!(!text.contains(SENSITIVE));
        assert!(!text.contains(BEARER));
        assert!(!text.contains("127.0.0.1"));
    }
}

#[derive(Clone)]
pub enum Reply {
    /// Accept the request and never answer.
    Silent,
    /// Send the status, then keep sending body bytes without finishing, so
    /// continuous progress must not reset the total deadline.
    Trickle { status: u16 },
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub body: serde_json::Value,
}

pub struct Server {
    pub url: String,
    count: Arc<AtomicUsize>,
    requests: mpsc::UnboundedReceiver<Request>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    pub async fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let (send, requests) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            // Dropping this set aborts every connection, including stalled peers.
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        seen.fetch_add(1, Ordering::SeqCst);
                        let send = send.clone();
                        let reply = reply.clone();
                        connections.spawn(async move { respond(socket, send, reply).await });
                    }
                    Some(done) = connections.join_next() => { done.unwrap(); }
                }
            }
        });
        Self {
            url,
            count,
            requests,
            task,
        }
    }

    pub async fn request(&mut self) -> Request {
        bounded(self.requests.recv())
            .await
            .expect("request captured")
    }

    /// Accepted connections. A retry opens another connection to this
    /// single-response peer before the client can report its failure.
    pub fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    pub async fn stop(mut self) {
        self.task.abort();
        let error = (&mut self.task)
            .await
            .expect_err("server runs until stopped");
        assert!(error.is_cancelled(), "loopback fixture failed");
    }
}

async fn respond(mut socket: TcpStream, send: mpsc::UnboundedSender<Request>, reply: Reply) {
    let mut bytes = Vec::new();
    let end = loop {
        let mut chunk = [0; 8192];
        let n = socket.read(&mut chunk).await.unwrap();
        assert_ne!(n, 0);
        bytes.extend_from_slice(&chunk[..n]);
        assert!(bytes.len() < 64 * 1024);
        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let mut lines = headers.lines();
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap().to_owned();
    let path = first.next().unwrap().to_owned();
    let mut len = 0;
    let mut authenticated = false;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                len = value.trim().parse().unwrap();
            }
            if key.eq_ignore_ascii_case("authorization") {
                authenticated = value.trim() == format!("Bearer {BEARER}");
            }
        }
    }
    assert!(authenticated, "synthetic request must be authenticated");
    assert!(len < 64 * 1024);
    while bytes.len() < end + len {
        let mut chunk = [0; 8192];
        let n = socket.read(&mut chunk).await.unwrap();
        assert_ne!(n, 0);
        bytes.extend_from_slice(&chunk[..n]);
    }
    let body = if len == 0 {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes[end..end + len]).expect("synthetic JSON request")
    };
    let _ = send.send(Request { method, path, body });
    match reply {
        Reply::Silent => std::future::pending::<()>().await,
        Reply::Trickle { status } => {
            let headers = format!(
                "HTTP/1.1 {status} Test\r\ncontent-length: 1048576\r\nconnection: close\r\n\r\n"
            );
            if socket.write_all(headers.as_bytes()).await.is_err() {
                return;
            }
            loop {
                if socket.write_all(b" ").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}
