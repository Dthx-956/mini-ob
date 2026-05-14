// ==================== src/agent/mod.rs ====================
//! mini-obs/agent/mod.rs
//! 边缘日志采集与压缩存储引擎 —— 模块入口
//!
//! 当前状态：
//! - collector / compressor / index / format 已完成并可用
//! - storage 为旧版实现，待后续重构接入 format.rs 规范
//! - 本 mod.rs 仅做模块声明与重新导出，不耦合 storage 内部格式细节

pub mod collector;
pub mod compressor;
pub mod index;
pub mod storage;

// ---------- 重新导出：简化外部调用 ----------
pub use collector::{Collector, CollectorConfig, SourceType};
pub use compressor::{Compressor, CompressorConfig, DictTrainer};
pub use index::{Index, IndexStats};

// storage 模块保留公开，但外部建议仅通过以下类型交互，避免依赖其内部旧格式
pub use storage::{StorageEngine, StorageConfig, StorageStats};

// ---------- 集成类型（可选，展示模块协作关系） ----------
use std::io;
use std::path::Path;
use std::sync::mpsc::Receiver;
use std::time::Duration;

/// 边缘 Agent 运行时句柄（轻量封装，不深入 storage 内部格式）
///
/// 使用示例：
/// ```ignore
/// use mini_obs::agent::AgentHandle;
/// let agent = AgentHandle::open("/data/mini-obs", "app").unwrap();
/// agent.start_tail("/var/log/app.log").unwrap();
/// // 日志自动流经 collector -> compressor -> storage
/// ```
pub struct AgentHandle {
    pub config: AgentConfig,
    // 运行时组件由调用方按需组合，mod.rs 仅提供类型聚合
}

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub data_dir: String,
    pub service_name: String,
    pub collector_interval: Duration,
    pub storage_config: StorageConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            data_dir: "/var/lib/mini-obs".to_string(),
            service_name: "app".to_string(),
            collector_interval: Duration::from_millis(100),
            storage_config: StorageConfig::default(),
        }
    }
}

impl AgentHandle {
    /// 初始化存储目录与索引（不启动采集）
    pub fn open(data_dir: impl AsRef<Path>, service: &str) -> io::Result<Self> {
        let _ = Index::open(data_dir.as_ref())?; // 确保索引目录存在
        Ok(Self {
            config: AgentConfig {
                data_dir: data_dir.as_ref().to_string_lossy().to_string(),
                service_name: service.to_string(),
                ..Default::default()
            },
        })
    }

    /// 创建采集器（返回接收端，由调用方决定如何处理，如送入 storage）
    pub fn create_collector(
        &self,
        source: SourceType,
    ) -> io::Result<(Collector, Receiver<crate::shared::format::LogLine>)> {
        Collector::start(CollectorConfig {
            source,
            poll_interval: self.config.collector_interval,
            service_name: self.config.service_name.clone(),
        })
    }

    /// 创建压缩器（字典可选）
    pub fn create_compressor(&self, dict: Option<Vec<u8>>) -> Compressor {
        Compressor::new(CompressorConfig {
            zstd_level: self.config.storage_config.compression_level,
            dict,
            ..Default::default()
        })
    }
}