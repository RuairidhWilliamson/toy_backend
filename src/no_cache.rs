use std::task::{Context, Poll};

use axum::{
    body::Body,
    http::{HeaderValue, Request, header::CACHE_CONTROL},
    response::Response,
};
use futures::future::BoxFuture;
use tower::{Layer, Service};

#[derive(Debug, Clone)]
pub struct NoCacheLayer;

impl<S> Layer<S> for NoCacheLayer {
    type Service = NoCacheMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        NoCacheMiddleware { inner }
    }
}

#[derive(Debug, Clone)]
pub struct NoCacheMiddleware<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for NoCacheMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let future = self.inner.call(request);
        Box::pin(async move {
            let mut response: Response = future.await?;
            let headers = response.headers_mut();
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            Ok(response)
        })
    }
}
