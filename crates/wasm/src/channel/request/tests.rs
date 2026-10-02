use super::*;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    task::Wake,
};
use wasm_bindgen_test::wasm_bindgen_test;

fn state() -> Rc<RequestState> {
    Rc::new(RequestState {
        io: RefCell::new(Some(RequestIo {
            request: None,
            decoder: None,
            request_hasher: None,
            request_finished: false,
        })),
        closed: Cell::new(false),
        waker: RefCell::new(None),
    })
}

struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[wasm_bindgen_test]
fn pending_operations_exclude_reentry_and_cancellation_notifications_them() {
    let state = state();
    let (operation, io) = Operation::begin(&state).unwrap();
    assert!(Operation::begin(&state).is_err());
    assert!(
        !state.closed.get(),
        "reentry rejection must not cancel the original operation"
    );
    let notifications = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&notifications));
    let mut cx = std::task::Context::from_waker(&waker);
    let pending = state.run(std::future::pending::<Result<(), Error>>());
    let mut pending = std::pin::pin!(pending);
    assert!(pending.as_mut().poll(&mut cx).is_pending());
    state.close();
    assert_eq!(notifications.0.load(Ordering::SeqCst), 1);
    assert!(matches!(
        pending.as_mut().poll(&mut cx),
        Poll::Ready(Err(_))
    ));
    assert!(
        operation.commit(io).is_err(),
        "cancelled state must never be restored"
    );
    assert!(Operation::begin(&state).is_err());
}

#[wasm_bindgen_test]
async fn callback_cancellation_rejects_even_a_completed_crypto_operation() {
    let state = state();
    let (operation, io) = Operation::begin(&state).unwrap();
    let result = state
        .run(async {
            state.close();
            Ok(())
        })
        .await;
    assert!(result.is_err());
    assert!(operation.commit(io).is_err());
}

#[wasm_bindgen_test]
fn failed_operation_consumes_state_but_completed_operations_can_continue() {
    let state = state();
    let (operation, io) = Operation::begin(&state).unwrap();
    operation.commit(io).unwrap();
    let (operation, _io) = Operation::begin(&state).unwrap();
    drop(operation);
    assert!(Operation::begin(&state).is_err());
}
