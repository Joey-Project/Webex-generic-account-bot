use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, bail};

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

    pub(crate) fn check(&self, operation: &str) -> Result<()> {
        if self.cancellation.is_cancelled() {
            bail!("{operation} was cancelled");
        }
        if Instant::now() >= self.deadline {
            bail!("{operation} exceeded its work deadline");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
