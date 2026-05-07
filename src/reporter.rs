use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

pub enum CrackEvent {
    Progress { tested: u64, total: u64 },
    Cracked { line: String },
    Done { found: usize },
}

pub struct Reporter {
    bar: ProgressBar,
    tx: Option<Sender<CrackEvent>>,
    total: u64,
    cancel: Arc<AtomicBool>,
}

impl Reporter {
    pub fn cli(total: u64) -> Self {
        let bar = ProgressBar::new(total);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("\n[{elapsed_precise}] [{bar:40}] {pos}/{len} ({percent}%)\n")
                .unwrap()
                .progress_chars("=> "),
        );
        Self {
            bar,
            tx: None,
            total,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn tui(total: u64, tx: Sender<CrackEvent>, cancel: Arc<AtomicBool>) -> Self {
        Self {
            bar: ProgressBar::hidden(),
            tx: Some(tx),
            total,
            cancel,
        }
    }

    pub fn silent() -> Self {
        Self {
            bar: ProgressBar::hidden(),
            tx: None,
            total: 0,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn inc(&self, n: u64) {
        self.bar.inc(n);
        if let Some(tx) = &self.tx {
            let _ = tx.send(CrackEvent::Progress {
                tested: self.bar.position(),
                total: self.total,
            });
        }
    }

    pub fn cracked(&self, line: String) {
        match &self.tx {
            Some(tx) => {
                let _ = tx.send(CrackEvent::Cracked { line });
            }
            None => self.bar.println(line),
        }
    }

    pub fn finish(&self, found: usize) {
        self.bar.finish();
        if let Some(tx) = &self.tx {
            let _ = tx.send(CrackEvent::Done { found });
        }
    }
}
