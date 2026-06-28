use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};

const STUCK_WORK_EXIT_CODE: i32 = 70;

#[derive(Debug, thiserror::Error)]
pub(crate) enum WorkBudgetError {
    #[error("{operation} was cancelled")]
    Cancelled { operation: String },
    #[error("{operation} exceeded its work deadline")]
    Deadline { operation: String },
}

impl WorkBudgetError {
    pub(crate) fn cancelled(operation: impl Into<String>) -> Self {
        Self::Cancelled {
            operation: operation.into(),
        }
    }
}

pub(crate) async fn run_blocking_with_process_watchdog<F, T>(
    operation: &'static str,
    hard_timeout: Duration,
    work: F,
) -> Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let deadline = Instant::now() + hard_timeout;
    let (completed, completion) = mpsc::channel();
    let (confirmed, confirmation) = tokio::sync::oneshot::channel();
    thread::Builder::new()
        .name("webex-bounded-work".to_owned())
        .spawn(move || {
            match completion.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(completed_at) if completed_at <= deadline => {
                    let _ = confirmed.send(());
                }
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {
                    tracing::error!(operation, "blocking work exceeded its process deadline");
                    std::process::exit(STUCK_WORK_EXIT_CODE);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {}
            }
        })
        .context("failed to start the blocking-work process watchdog")?;

    let result = tokio::task::spawn_blocking(move || {
        let result = work();
        let _ = completed.send(Instant::now());
        result
    })
    .await
    .with_context(|| format!("{operation} task failed"))?;
    confirmation
        .await
        .with_context(|| format!("{operation} watchdog did not confirm completion"))?;
    Ok(result)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct WorkCancellation {
    cancelled: Arc<AtomicBool>,
}

impl WorkCancellation {
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WorkBudget {
    deadline: Instant,
    cancellation: WorkCancellation,
}

impl WorkBudget {
    pub(crate) fn after(duration: Duration) -> Self {
        Self::with_cancellation(duration, WorkCancellation::default())
    }

    pub(crate) fn with_cancellation(duration: Duration, cancellation: WorkCancellation) -> Self {
        Self {
            deadline: Instant::now() + duration,
            cancellation,
        }
    }

    pub(crate) fn check(&self, operation: &str) -> std::result::Result<(), WorkBudgetError> {
        if self.cancellation.is_cancelled() {
            return Err(WorkBudgetError::Cancelled {
                operation: operation.to_owned(),
            });
        }
        if Instant::now() >= self.deadline {
            return Err(WorkBudgetError::Deadline {
                operation: operation.to_owned(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WATCHDOG_CHILD_ENV: &str = "WEBEX_WORK_WATCHDOG_CHILD";

    #[test]
    fn expired_deadline_fails_closed() {
        let deadline = WorkBudget::after(Duration::ZERO);
        assert!(deadline.check("test work").is_err());
    }

    #[test]
    fn cancellation_fails_closed() {
        let cancellation = WorkCancellation::default();
        let budget = WorkBudget::with_cancellation(Duration::from_secs(60), cancellation.clone());
        cancellation.cancel();
        assert!(budget.check("test work").is_err());
    }

    #[tokio::test]
    async fn process_watchdog_disarms_when_blocking_work_finishes() {
        let result = run_blocking_with_process_watchdog("test work", Duration::from_secs(5), || 42)
            .await
            .unwrap();

        assert_eq!(result, 42);
    }

    #[test]
    fn process_watchdog_child_helper() {
        if std::env::var_os(WATCHDOG_CHILD_ENV).is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = runtime.block_on(run_blocking_with_process_watchdog(
            "stuck test work",
            Duration::from_millis(50),
            || {
                thread::sleep(Duration::from_secs(10));
            },
        ));
        panic!("stuck child work escaped the process watchdog");
    }

    #[test]
    fn process_watchdog_hard_stops_stuck_blocking_work() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "work_budget::tests::process_watchdog_child_helper",
                "--nocapture",
            ])
            .env(WATCHDOG_CHILD_ENV, "1")
            .status()
            .unwrap();

        assert_eq!(status.code(), Some(STUCK_WORK_EXIT_CODE));
    }
}
