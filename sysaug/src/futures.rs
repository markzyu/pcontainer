use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

// Zero cost fence that can be stored in a struct
enum PendingOrReady<T> {
    Ready(Option<T>),
    Pending,
}

impl<T> Future for PendingOrReady<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            PendingOrReady::Ready(value_opt) => {
                Poll::Ready(value_opt.take().expect("polled after ready"))
            }
            PendingOrReady::Pending => Poll::Pending,
        }
    }
}

