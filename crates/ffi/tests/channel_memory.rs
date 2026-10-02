//! Allocation accounting belongs in a separate test process so concurrent unit
//! tests cannot contaminate the session's retained and temporary memory totals.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use stogas_verifier::channel::ratchet::{ChunkSize, InitialKey, MAX_SKIPPED_KEYS, Peer};

struct Counting;
static USED: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
#[global_allocator]
static ALLOCATOR: Counting = Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwards the unchanged layout to the system allocator.
        let value = unsafe { System.alloc(layout) };
        if !value.is_null() {
            PEAK.fetch_max(
                USED.fetch_add(layout.size(), Relaxed) + layout.size(),
                Relaxed,
            );
        }
        value
    }
    unsafe fn dealloc(&self, value: *mut u8, layout: Layout) {
        USED.fetch_sub(layout.size(), Relaxed);
        // SAFETY: returns the original allocation with its original layout.
        unsafe { System.dealloc(value, layout) };
    }
}

#[test]
fn full_skipped_window_and_authenticated_replacement_fit_the_embedding_reservation() {
    for width in [32, 34, 1152] {
        let size = ChunkSize::new(width).unwrap();
        let initial = InitialKey::generate().unwrap();
        let mut sender = Peer::initiator(&[1; 32], size, initial.public_key());
        let baseline = USED.load(Relaxed);
        let mut receiver = Peer::responder(&[1; 32], size, initial);
        let mut largest_peak = 0;
        let mut largest_retained = 0;
        for round in 0..4 {
            for _ in 0..MAX_SKIPPED_KEYS {
                drop(sender.send().unwrap());
            }
            let packet = sender.send().unwrap();
            let before = USED.load(Relaxed);
            PEAK.store(before, Relaxed);
            receiver
                .receive(&packet.header, round, |secret| {
                    assert_eq!(*secret, *packet.secret);
                    Ok(())
                })
                .unwrap();
            let retained = USED.load(Relaxed).saturating_sub(baseline);
            let peak = retained + PEAK.load(Relaxed).saturating_sub(USED.load(Relaxed));
            largest_peak = largest_peak.max(peak);
            largest_retained = largest_retained.max(retained);
        }
        // The embedding reserves three MiB including the smaller active KEM and
        // admission state. The gap cache is its dominant allocation. This bound
        // intentionally leaves room for a different standard-library allocator.
        assert!(
            largest_peak < 3 * 1024 * 1024,
            "width {width}: {largest_peak}"
        );
        println!("width={width} retained={largest_retained} peak={largest_peak}");
    }
}
