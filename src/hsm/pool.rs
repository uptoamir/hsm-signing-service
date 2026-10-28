//! Bounded pool of PKCS#11 sessions.
//!
//! PKCS#11 sessions are a scarce resource: tokens cap the number of
//! concurrent sessions, every call is a synchronous (blocking) FFI call, and a
//! session carries state (login, an active multi-part operation) that must not
//! be shared across threads. This pool therefore:
//!
//! * owns at most `capacity` sessions, opened eagerly at startup so that
//!   misconfiguration fails fast and the first requests do not pay the
//!   open-and-login cost;
//! * bounds concurrency with a semaphore: at most `capacity` token operations
//!   are in flight, and a caller waits at most `acquire_timeout` for a permit
//!   before receiving [`HsmError::Busy`] (that is the backpressure signal the
//!   API turns into `503 + Retry-After`);
//! * runs every token call on Tokio's blocking thread pool so FFI never stalls
//!   the async runtime;
//! * applies `op_timeout` to each operation. A blocking FFI call cannot be
//!   cancelled, so on timeout the caller gets an error immediately while the
//!   worker keeps its permit until the call really returns -- the concurrency
//!   bound is never violated;
//! * recycles sessions whose last operation returned an error that indicates
//!   the session is unusable (see [`HsmError::invalidates_session`]), and
//!   lazily reopens replacements.
//!
//! Object handles are cached per session: PKCS#11 does not promise that a
//! handle obtained in one session is valid in another.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cryptoki::context::Pkcs11;
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::object::ObjectHandle;
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use parking_lot::Mutex;
use tokio::sync::Semaphore;

use crate::error::HsmError;
use crate::hsm::PoolStats;

#[derive(Debug, Clone)]
pub struct PoolOptions {
    /// Maximum number of sessions, and therefore of concurrent token calls.
    pub capacity: usize,
    /// How long a caller waits for a free session before `HsmError::Busy`.
    pub acquire_timeout: Duration,
    /// Upper bound on a single token operation as observed by the caller.
    pub op_timeout: Duration,
}

/// A session plus its private cache of object handles.
pub struct PooledSession {
    pub session: Session,
    handles: HashMap<String, ObjectHandle>,
    ops: u64,
}

impl PooledSession {
    pub fn cached_handle(&self, key: &str) -> Option<ObjectHandle> {
        self.handles.get(key).copied()
    }

    pub fn cache_handle(&mut self, key: String, handle: ObjectHandle) {
        self.handles.insert(key, handle);
    }

    pub fn forget_handle(&mut self, key: &str) {
        self.handles.remove(key);
    }
}

pub struct SessionPool {
    ctx: Pkcs11,
    slot: Slot,
    pin: AuthPin,
    idle: Mutex<Vec<PooledSession>>,
    permits: Arc<Semaphore>,
    opts: PoolOptions,
    in_use: AtomicUsize,
    waiters: AtomicUsize,
    opened: AtomicU64,
    recycled: AtomicU64,
    acquire_timeouts: AtomicU64,
}

impl SessionPool {
    pub fn new(
        ctx: Pkcs11,
        slot: Slot,
        pin: AuthPin,
        opts: PoolOptions,
    ) -> Result<Arc<Self>, HsmError> {
        if opts.capacity == 0 {
            return Err(HsmError::Internal(
                "session pool capacity must be at least 1".into(),
            ));
        }
        let pool = Arc::new(Self {
            ctx,
            slot,
            pin,
            idle: Mutex::new(Vec::with_capacity(opts.capacity)),
            permits: Arc::new(Semaphore::new(opts.capacity)),
            opts: opts.clone(),
            in_use: AtomicUsize::new(0),
            waiters: AtomicUsize::new(0),
            opened: AtomicU64::new(0),
            recycled: AtomicU64::new(0),
            acquire_timeouts: AtomicU64::new(0),
        });
        let mut warm = Vec::with_capacity(opts.capacity);
        for _ in 0..opts.capacity {
            warm.push(pool.open_session()?);
        }
        *pool.idle.lock() = warm;
        tracing::info!(
            capacity = opts.capacity,
            slot = pool.slot.id(),
            acquire_timeout_ms = opts.acquire_timeout.as_millis() as u64,
            op_timeout_ms = opts.op_timeout.as_millis() as u64,
            "HSM session pool ready"
        );
        Ok(pool)
    }

    pub fn context(&self) -> &Pkcs11 {
        &self.ctx
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn options(&self) -> &PoolOptions {
        &self.opts
    }

    fn open_session(&self) -> Result<PooledSession, HsmError> {
        let session = self.ctx.open_rw_session(self.slot)?;
        // Login state is per token and per application in PKCS#11: once any
        // session of this process is logged in, all of them are. A second login
        // therefore legitimately answers "already logged in".
        match session.login(UserType::User, Some(&self.pin)) {
            Ok(()) => {}
            Err(Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(e) => return Err(e.into()),
        }
        self.opened.fetch_add(1, Ordering::Relaxed);
        Ok(PooledSession {
            session,
            handles: HashMap::new(),
            ops: 0,
        })
    }

    fn checkout(&self) -> Result<PooledSession, HsmError> {
        if let Some(s) = self.idle.lock().pop() {
            return Ok(s);
        }
        // Only reached after a session was discarded; the semaphore guarantees
        // the number of live sessions never exceeds `capacity`.
        self.open_session()
    }

    fn checkin(&self, s: PooledSession) {
        self.idle.lock().push(s);
    }

    fn discard(&self, s: PooledSession) {
        self.recycled.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("hsm_sessions_recycled_total").increment(1);
        drop(s); // `Session::drop` closes the session on the token.
    }

    /// Runs `f` against a pooled session on the blocking thread pool.
    ///
    /// `op` is a static label used for metrics and logs.
    pub async fn with_session<T, F>(self: &Arc<Self>, op: &'static str, f: F) -> Result<T, HsmError>
    where
        F: FnOnce(&mut PooledSession) -> Result<T, HsmError> + Send + 'static,
        T: Send + 'static,
    {
        let wait_started = Instant::now();
        self.waiters.fetch_add(1, Ordering::Relaxed);
        let acquired = tokio::time::timeout(
            self.opts.acquire_timeout,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await;
        self.waiters.fetch_sub(1, Ordering::Relaxed);
        let permit = match acquired {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return Err(HsmError::Unavailable("session pool is closed".into())),
            Err(_elapsed) => {
                self.acquire_timeouts.fetch_add(1, Ordering::Relaxed);
                metrics::counter!("hsm_pool_acquire_timeouts_total", "op" => op).increment(1);
                return Err(HsmError::Busy(self.opts.acquire_timeout));
            }
        };
        metrics::histogram!("hsm_pool_wait_seconds").record(wait_started.elapsed().as_secs_f64());

        let pool = Arc::clone(self);
        let op_timeout = self.opts.op_timeout;
        let join = tokio::task::spawn_blocking(move || {
            let _permit = permit; // held until the FFI call has really returned
            let _in_use = CounterGuard::new(&pool.in_use);
            let mut session = pool.checkout()?;
            let started = Instant::now();
            let result = f(&mut session);
            session.ops += 1;
            let outcome = if result.is_ok() { "ok" } else { "error" };
            metrics::histogram!("hsm_operation_duration_seconds", "op" => op, "outcome" => outcome)
                .record(started.elapsed().as_secs_f64());
            metrics::counter!("hsm_operations_total", "op" => op, "outcome" => outcome)
                .increment(1);
            match &result {
                Err(e) if e.invalidates_session() => {
                    tracing::warn!(op, error = %e, ops = session.ops, "discarding HSM session after error");
                    pool.discard(session);
                }
                _ => pool.checkin(session),
            }
            result
        });

        match tokio::time::timeout(op_timeout, join).await {
            Ok(Ok(result)) => result,
            Ok(Err(join_err)) => Err(HsmError::Internal(format!(
                "HSM worker task failed: {join_err}"
            ))),
            Err(_elapsed) => {
                // The blocking call keeps running (and keeps its permit) until
                // the token answers; the caller simply stops waiting for it.
                metrics::counter!("hsm_operation_timeouts_total", "op" => op).increment(1);
                Err(HsmError::Timeout(op_timeout))
            }
        }
    }

    pub fn stats(&self) -> PoolStats {
        PoolStats {
            capacity: self.opts.capacity,
            in_use: self.in_use.load(Ordering::Relaxed),
            idle: self.idle.lock().len(),
            waiters: self.waiters.load(Ordering::Relaxed),
            sessions_opened: self.opened.load(Ordering::Relaxed),
            sessions_recycled: self.recycled.load(Ordering::Relaxed),
            acquire_timeouts: self.acquire_timeouts.load(Ordering::Relaxed),
        }
    }
}

/// Increments a counter for the lifetime of the guard; decrements even on panic.
struct CounterGuard<'a>(&'a AtomicUsize);

impl<'a> CounterGuard<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for CounterGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
