//! 模板提取诊断测试
//!
//! 对 HDFS_2k.log 进行模板提取，分析：
//! - 模板总数
//! - 平均每条消息参数数量
//! - 退化模板数量（全 Param 或 Literal 过少）
//! - 参数类型分布
//!
//! 用于验证修复后的 TemplateExtractor 不会将语法结构不同但 token 数相同的
//! 消息错误合并为退化模板。

use std::fs;
use std::path::PathBuf;

use mini_obs::agent::collector::parse_line;
use mini_obs::agent::template::{ParamType, TemplateExtractor, TemplatePart};

const HDFS_LOG_PATH: &str = "tmp/HDFS_2k.log";

#[test]
fn test_hdfs_template_extraction_diagnostic() {
    let log_path = PathBuf::from(HDFS_LOG_PATH);
    assert!(
        log_path.exists(),
        "测试日志 {} 不存在，请先准备该文件",
        HDFS_LOG_PATH
    );

    let raw_text = fs::read_to_string(&log_path).expect("读取日志文件失败");
    let logs: Vec<_> = raw_text
        .lines()
        .filter_map(|line| parse_line(line, "hdfs"))
        .collect();

    assert!(!logs.is_empty(), "未能解析出任何日志行");

    let batch = TemplateExtractor::extract(&logs);

    // 统计模板信息
    let mut total_params = 0usize;
    let mut degenerate_templates = 0usize;
    let mut type_counts: std::collections::HashMap<ParamType, usize> =
        std::collections::HashMap::new();

    for t in &batch.templates {
        let param_count = t
            .parts
            .iter()
            .filter(|p| matches!(p, TemplatePart::Param))
            .count();
        let literal_count = t.parts.len() - param_count;
        total_params += param_count;

        // 退化标准：Literal 少于 2 个，或参数占比超过 80%
        if literal_count < 2 || param_count > literal_count * 4 {
            degenerate_templates += 1;
        }
    }

    for rec in &batch.records {
        for p in &rec.params {
            *type_counts.entry(p.ty).or_default() += 1;
        }
    }

    let avg_params = if !batch.records.is_empty() {
        total_params as f64 / batch.records.len() as f64
    } else {
        0.0
    };

    println!("\n========== HDFS_2k.log 模板提取诊断报告 ==========");
    println!("日志行数:           {}", logs.len());
    println!("模板总数:           {}", batch.templates.len());
    println!("参数总数:           {}", total_params);
    println!("平均每行参数:       {:.2}", avg_params);
    println!("退化模板数:         {}", degenerate_templates);
    println!(
        "退化比例:           {:.1}%",
        degenerate_templates as f64 / batch.templates.len() as f64 * 100.0
    );
    println!();
    println!("参数类型分布:");
    let mut type_vec: Vec<_> = type_counts.iter().collect();
    type_vec.sort_by_key(|(k, _)| **k as u8);
    for (ty, count) in type_vec {
        let name = match ty {
            ParamType::String => "String",
            ParamType::Integer => "Integer",
            ParamType::Hex => "Hex",
            ParamType::IPv4 => "IPv4",
            ParamType::BlockId => "BlockId",
            ParamType::IPv4Port => "IPv4Port",
            ParamType::Timestamp => "Timestamp",
            ParamType::Path => "Path",
        };
        println!("  {:12} {}", name, count);
    }

    // 打印前 10 个模板示例
    println!();
    println!("前 10 个模板示例:");
    for (i, t) in batch.templates.iter().take(10).enumerate() {
        let sig: String = t
            .parts
            .iter()
            .map(|p| match p {
                TemplatePart::Literal(s) => s.clone(),
                TemplatePart::Param => "<*>".to_string(),
            })
            .collect();
        let param_count = t
            .parts
            .iter()
            .filter(|p| matches!(p, TemplatePart::Param))
            .count();
        let rec_count = batch.records.iter().filter(|r| r.pat_id == t.id).count();
        println!(
            "  template {:2}: params={:2}, records={:4}, sig={}",
            i, param_count, rec_count, sig
        );
    }
    println!("==================================================\n");

    // 断言：退化模板应极少
    assert!(
        degenerate_templates <= 2,
        "退化模板过多: {} / {}",
        degenerate_templates,
        batch.templates.len()
    );

    // 断言：模板数量应远小于日志行数（证明有效聚类）
    assert!(
        batch.templates.len() < logs.len() / 10,
        "模板数量过多，聚类效果不佳: {} 模板 / {} 行",
        batch.templates.len(),
        logs.len()
    );
}
