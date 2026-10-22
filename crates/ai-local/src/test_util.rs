//! Minimal test-only executor: the local mock model's future never suspends,
//! so a single poll (with a safety bound) is enough and no async runtime
//! dependency is needed in this crate.

use std::future::Future;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

fn noop(_: *const ()) {}

fn clone(_: *const ()) -> RawWaker {
    RawWaker::new(std::ptr::null(), &VTABLE)
}

static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);

/// Poll a future to completion. Panics if it stays pending (the mock model
/// must not await anything).
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    for _ in 0..1024 {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
    panic!("future did not complete without an executor");
}
