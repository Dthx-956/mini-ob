//! mini-obs
//! 边缘原生轻量级日志管理系统 —— 库入口

pub mod agent;
pub mod shared;

#[cfg(test)]
pub mod test_util {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub fn temp_dir(prefix: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("{}-{}-{}-{}", prefix, pid, ts, n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
