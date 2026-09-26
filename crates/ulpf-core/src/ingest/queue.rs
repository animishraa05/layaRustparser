use anyhow::Result;
use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressurePolicy {
    Block,
    Drop,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct QueueStats {
    pub pushed: u64,
    pub dropped: u64,
    pub blocked: u64,
    pub current_len: usize,
}

pub trait LogQueue: Send + Sync {
    fn push(&self, b: Bytes) -> Result<()>;
    fn pop_batch(&self, max_batch_size: usize) -> Vec<Bytes>;
    fn stats(&self) -> QueueStats;
}

struct MemoryQueueInner {
    queue: Mutex<VecDeque<Bytes>>,
    not_empty: Condvar,
    not_full: Condvar,
    capacity: usize,
    policy: BackpressurePolicy,
    pushed: AtomicU64,
    dropped: AtomicU64,
    blocked: AtomicU64,
}

pub struct MemoryQueue {
    inner: Arc<MemoryQueueInner>,
}

impl MemoryQueue {
    pub fn new(capacity: usize, policy: BackpressurePolicy) -> Self {
        Self {
            inner: Arc::new(MemoryQueueInner {
                queue: Mutex::new(VecDeque::with_capacity(capacity)),
                not_empty: Condvar::new(),
                not_full: Condvar::new(),
                capacity,
                policy,
                pushed: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                blocked: AtomicU64::new(0),
            }),
        }
    }
}

impl LogQueue for MemoryQueue {
    fn push(&self, b: Bytes) -> Result<()> {
        let inner = &self.inner;
        let mut queue = inner.queue.lock().unwrap();

        match inner.policy {
            BackpressurePolicy::Block => {
                while queue.len() >= inner.capacity {
                    inner.blocked.fetch_add(1, Ordering::Relaxed);
                    queue = inner.not_full.wait(queue).unwrap();
                }
                queue.push_back(b);
                inner.pushed.fetch_add(1, Ordering::Relaxed);
                inner.not_empty.notify_one();
                Ok(())
            }
            BackpressurePolicy::Drop => {
                if queue.len() >= inner.capacity {
                    inner.dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                queue.push_back(b);
                inner.pushed.fetch_add(1, Ordering::Relaxed);
                inner.not_empty.notify_one();
                Ok(())
            }
        }
    }

    fn pop_batch(&self, max_batch_size: usize) -> Vec<Bytes> {
        let inner = &self.inner;
        let mut queue = inner.queue.lock().unwrap();

        while queue.is_empty() {
            queue = inner.not_empty.wait(queue).unwrap();
        }

        let batch_size = std::cmp::min(max_batch_size, queue.len());
        let mut batch = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            if let Some(item) = queue.pop_front() {
                batch.push(item);
            }
        }

        if batch_size > 0 {
            inner.not_full.notify_all();
        }

        batch
    }

    fn stats(&self) -> QueueStats {
        let inner = &self.inner;
        let queue = inner.queue.lock().unwrap();
        QueueStats {
            pushed: inner.pushed.load(Ordering::Relaxed),
            dropped: inner.dropped.load(Ordering::Relaxed),
            blocked: inner.blocked.load(Ordering::Relaxed),
            current_len: queue.len(),
        }
    }
}

#[cfg(feature = "broker")]
pub mod broker {
    use super::{BackpressurePolicy, LogQueue, QueueStats};
    use anyhow::Result;
    use bytes::Bytes;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    pub struct BrokerQueue {
        pushed: AtomicU64,
        dropped: AtomicU64,
        blocked: AtomicU64,
    }

    impl BrokerQueue {
        pub fn new(_capacity: usize, _policy: BackpressurePolicy) -> Self {
            Self {
                pushed: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                blocked: AtomicU64::new(0),
            }
        }
    }

    impl LogQueue for BrokerQueue {
        fn push(&self, _b: Bytes) -> Result<()> {
            self.pushed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn pop_batch(&self, _max_batch_size: usize) -> Vec<Bytes> {
            Vec::new()
        }

        fn stats(&self) -> QueueStats {
            QueueStats {
                pushed: self.pushed.load(Ordering::Relaxed),
                dropped: self.dropped.load(Ordering::Relaxed),
                blocked: self.blocked.load(Ordering::Relaxed),
                current_len: 0,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BackpressurePolicy, LogQueue, MemoryQueue};
    use bytes::Bytes;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_memory_queue_basic_push_pop() {
        let queue = MemoryQueue::new(10, BackpressurePolicy::Block);
        queue.push(Bytes::from("test1")).unwrap();
        queue.push(Bytes::from("test2")).unwrap();

        let batch = queue.pop_batch(5);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], Bytes::from("test1"));
        assert_eq!(batch[1], Bytes::from("test2"));

        let stats = queue.stats();
        assert_eq!(stats.pushed, 2);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.blocked, 0);
        assert_eq!(stats.current_len, 0);
    }

    #[test]
    fn test_memory_queue_pop_batch_limit() {
        let queue = MemoryQueue::new(10, BackpressurePolicy::Block);
        for i in 0..10 {
            queue.push(Bytes::from(format!("item{}", i))).unwrap();
        }

        let batch = queue.pop_batch(3);
        assert_eq!(batch.len(), 3);
        let stats = queue.stats();
        assert_eq!(stats.current_len, 7);
    }

    #[test]
    fn test_memory_queue_drop_policy() {
        let queue = MemoryQueue::new(3, BackpressurePolicy::Drop);
        queue.push(Bytes::from("1")).unwrap();
        queue.push(Bytes::from("2")).unwrap();
        queue.push(Bytes::from("3")).unwrap();
        queue.push(Bytes::from("4")).unwrap();
        queue.push(Bytes::from("5")).unwrap();

        let stats = queue.stats();
        assert_eq!(stats.pushed, 3);
        assert_eq!(stats.dropped, 2);
        assert_eq!(stats.current_len, 3);

        let batch = queue.pop_batch(10);
        assert_eq!(batch.len(), 3);
    }

    #[test]
    fn test_memory_queue_block_policy_blocks_producer() {
        let queue = Arc::new(MemoryQueue::new(2, BackpressurePolicy::Block));
        queue.push(Bytes::from("1")).unwrap();
        queue.push(Bytes::from("2")).unwrap();

        let queue_clone = queue.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            queue_clone.push(Bytes::from("3")).unwrap();
        });

        thread::sleep(Duration::from_millis(20));
        let stats = queue.stats();
        assert!(stats.blocked > 0);

        let _ = queue.pop_batch(1);
        handle.join().unwrap();

        let stats = queue.stats();
        assert_eq!(stats.pushed, 3);
    }

    #[test]
    fn test_memory_queue_concurrent_producers_consumers() {
        let queue = Arc::new(MemoryQueue::new(100, BackpressurePolicy::Block));
        let num_producers = 4;
        let items_per_producer = 25;

        let mut handles = Vec::new();
        for p in 0..num_producers {
            let q = queue.clone();
            handles.push(thread::spawn(move || {
                for i in 0..items_per_producer {
                    q.push(Bytes::from(format!("p{}i{}", p, i))).unwrap();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let mut total_popped = 0;
        while total_popped < num_producers * items_per_producer {
            let batch = queue.pop_batch(10);
            total_popped += batch.len();
        }

        let stats = queue.stats();
        assert_eq!(stats.pushed, 100);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.current_len, 0);
    }

    #[test]
    fn test_memory_queue_empty_pop_waits() {
        let queue = Arc::new(MemoryQueue::new(10, BackpressurePolicy::Block));
        let queue_clone = queue.clone();

        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            queue_clone.push(Bytes::from("data")).unwrap();
        });

        let batch = queue.pop_batch(1);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0], Bytes::from("data"));

        handle.join().unwrap();
    }

    #[test]
    fn test_memory_queue_stats_accuracy() {
        let queue = MemoryQueue::new(5, BackpressurePolicy::Block);
        queue.push(Bytes::from("a")).unwrap();
        queue.push(Bytes::from("b")).unwrap();

        let _ = queue.pop_batch(1);

        queue.push(Bytes::from("c")).unwrap();

        let stats = queue.stats();
        assert_eq!(stats.pushed, 3);
        assert_eq!(stats.current_len, 2);
    }
}
