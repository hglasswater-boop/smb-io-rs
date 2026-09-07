use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Notify;

struct Inner {
    generation: AtomicU64,
    notify: Notify,
}

/// Cloneable generation token used to invalidate in-flight SMB READ work.
///
/// Advancing the generation is synchronous and immediately wakes any client wait that is watching
/// the old generation. The actual SMB2 CANCEL packets are emitted by the READ engine so transport
/// ownership stays in one place.
#[derive(Clone)]
pub struct ReadCancellationToken {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for ReadCancellationToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReadCancellationToken")
            .field("generation", &self.generation())
            .finish()
    }
}

impl Default for ReadCancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadCancellationToken {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                generation: AtomicU64::new(0),
                notify: Notify::new(),
            }),
        }
    }

    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    pub fn is_current(&self, generation: u64) -> bool {
        self.generation() == generation
    }

    pub fn advance(&self) -> u64 {
        let next = self
            .inner
            .generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        self.inner.notify.notify_waiters();
        next
    }

    pub async fn wait_for_change(&self, generation: u64) -> u64 {
        loop {
            let notified = self.inner.notify.notified();
            let current = self.generation();
            if current != generation {
                return current;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn advancing_generation_wakes_waiter() {
        let token = ReadCancellationToken::new();
        let generation = token.generation();
        let waiter = token.clone();
        let task = tokio::spawn(async move { waiter.wait_for_change(generation).await });
        assert_eq!(token.advance(), generation + 1);
        assert_eq!(task.await.unwrap(), generation + 1);
    }
}
