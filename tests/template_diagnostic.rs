//! 压缩预处理诊断：对比纯 zstd 与 模板+zstd 的中间产物，定位效率损失来源

use std::fs;
use std::path::PathBuf;

use mini_obs::agent::template::{TemplateExtractor, TemplatePart, TypedParam};
use mini_obs::agent::{Compressor, CompressorConfig};
use mini_obs::shared::format::LogLine;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn parse_log_line(line: &str, service: &str, default_ts: u64) -> Option<LogLine> {
    let line = line.trim();
    if line.is_empty() { return None; }
    if line.starts_with('{') {
        if let Ok(log) = serde_json::from_str::<LogLine>(line) { return Some(log); }
    }
    let level = if line.contains("ERROR") || line.contains("Error") || line.contains("error") {
        "E"
    } else if line.contains("WARN") || line.contains("Warn") || line.contains("warn") {
        "W"
    } else if line.contains("DEBUG") || line.contains("Debug") {
        "D"
    } else {
        "I"
    };
    Some(LogLine { ts: default_ts, service: service.to_string(), level: level.to_string(), message: line.to_string() })
}

#[test]
fn diagnose_all_three_logs() {
    let files: &[(&str, &str)] = &[
        ("OpenSSH", "tmp/OpenSSH_2k.log"),
        ("OpenStack", "tmp/OpenStack_2k.log"),
        ("Android", "tmp/Android_2k.log"),
    ];

    println!("\n╔══════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                   🔬 模板提取 + 二进制编码 逐层诊断报告                          ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════╝");

    for (name, rel_path) in files {
        let path = project_root().join(rel_path);
        assert!(path.exists(), "{} 日志文件不存在: {}", name, path.display());
        let raw_bytes = fs::read(&path).unwrap();
        let raw_size = raw_bytes.len();
        let raw_text = String::from_utf8_lossy(&raw_bytes);
        let lines: Vec<&str> = raw_text.lines().filter(|l| !l.trim().is_empty()).collect();
        let n = lines.len();

        let base_ts = 1_000_000u64;
        let logs: Vec<LogLine> = lines.iter().enumerate()
            .filter_map(|(i, l)| parse_log_line(l, &name.to_lowercase(), base_ts + i as u64))
            .collect();

        // ── ① 纯 zstd ──
        let pure_zstd = zstd::encode_all(&raw_bytes[..], 3).unwrap();

        // ── ② 模板提取 ──
        let batch = TemplateExtractor::extract(&logs);
        let encoded = TemplateExtractor::encode_xor(&batch, 16);

        // ── 模板统计 ──
        use std::collections::HashMap;
        let mut total_params = 0usize;
        let mut total_param_bytes = 0usize;
        let mut params_per_rec = vec![];
        let mut total_literal_bytes = 0usize;
        let mut templates_all_params = 0usize;
        let mut all_template_literals = String::new(); // 全部模板 Literal 拼接

        for t in &batch.templates {
            let lit_count = t.parts.iter().filter(|p| matches!(p, TemplatePart::Literal(_))).count();
            let param_count = t.parts.len() - lit_count;
            if param_count == t.parts.len() && t.parts.len() > 0 { templates_all_params += 1; }
            for part in &t.parts {
                if let TemplatePart::Literal(s) = part {
                    total_literal_bytes += s.len();
                    all_template_literals.push_str(s);
                }
            }
        }

        for rec in &batch.records {
            let np = rec.params.len();
            total_params += np;
            params_per_rec.push(np);
            for p in &rec.params { total_param_bytes += p.bytes.len(); }
        }
        params_per_rec.sort();
        let avg_params = total_params as f64 / batch.records.len() as f64;
        let median_params = params_per_rec[params_per_rec.len() / 2];

        let mut pat_counts: HashMap<u16, usize> = HashMap::new();
        for rec in &batch.records { *pat_counts.entry(rec.pat_id).or_default() += 1; }
        let max_instances = pat_counts.values().max().unwrap_or(&0);
        let singletons = pat_counts.values().filter(|&&c| c == 1).count();

        // ── 二进制中间产物（zstd 压缩前）──
        let bin_before_zstd = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&(batch.templates.len() as u16).to_le_bytes());
            for t in &batch.templates {
                buf.extend_from_slice(&(t.parts.len() as u16).to_le_bytes());
                for part in &t.parts {
                    match part {
                        TemplatePart::Literal(s) => {
                            buf.push(0x01);
                            let bytes = s.as_bytes();
                            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                            buf.extend_from_slice(bytes);
                        }
                        TemplatePart::Param => { buf.push(0x02); }
                    }
                }
            }
            buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            for rec in &encoded {
                buf.extend_from_slice(&rec.ts_delta.to_le_bytes());
                buf.push(rec.svc_id);
                buf.push(rec.level.as_bytes()[0]);
                buf.extend_from_slice(&rec.pat_id.to_le_bytes());
                buf.extend_from_slice(&rec.param_encoding.ref_idx.to_le_bytes());
                buf.extend_from_slice(&(rec.param_encoding.data.len() as u32).to_le_bytes());
                buf.extend_from_slice(&rec.param_encoding.data);
            }
            buf
        };

        // 分解：模板字典部分 vs 记录部分
        let template_dict_size = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&(batch.templates.len() as u16).to_le_bytes());
            for t in &batch.templates {
                buf.extend_from_slice(&(t.parts.len() as u16).to_le_bytes());
                for part in &t.parts {
                    match part {
                        TemplatePart::Literal(s) => {
                            buf.push(0x01);
                            let bytes = s.as_bytes();
                            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                            buf.extend_from_slice(bytes);
                        }
                        TemplatePart::Param => { buf.push(0x02); }
                    }
                }
            }
            buf.len()
        };

        // 逐记录固定开销：ts_delta(8B) + svc_id(1B) + level(1B) + pat_id(2B) + ref_idx(2B) + data_len(4B) = 18B/条
        let record_fixed_overhead = encoded.len() * 18;

        // ── ② 模板+zstd ──
        let compressor = Compressor::new(CompressorConfig::default());
        let template_zstd = compressor.compress_batch(&logs).unwrap();

        // ── ②-b JSON+zstd ──
        let compressor_no_tpl = Compressor::new(CompressorConfig { enable_template: false, ..Default::default() });
        let json_zstd = compressor_no_tpl.compress_batch(&logs).unwrap();

        // ── 仅 messages+zstd（理论下界，无任何包装）──
        let messages_only: Vec<u8> = logs.iter().flat_map(|l| {
            let mut v = l.message.as_bytes().to_vec();
            v.push(b'\n');
            v
        }).collect();
        let msg_only_zstd = zstd::encode_all(&messages_only[..], 3).unwrap();

        // ── 输出 ──
        println!();
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  📁 {}", name);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  原始文件:         {:>8} bytes ({:.1} KB)  行数: {}", raw_size, raw_size as f64/1024.0, n);
        println!();
        println!("  ┌─ 压缩结果对比 ─────────────────────────────────────────────┐");
        println!("  │ ① 纯 zstd:       {:>8} bytes ({:>5.1} KB) → {:>5.2}x           │", pure_zstd.len(), pure_zstd.len() as f64/1024.0, raw_size as f64/pure_zstd.len() as f64);
        println!("  │ 仅message+zstd:   {:>8} bytes ({:>5.1} KB) → {:>5.2}x (理论上界)│", msg_only_zstd.len(), msg_only_zstd.len() as f64/1024.0, messages_only.len() as f64/msg_only_zstd.len() as f64);
        println!("  │ ②-b JSON+zstd:   {:>8} bytes ({:>5.1} KB) → {:>5.2}x           │", json_zstd.len(), json_zstd.len() as f64/1024.0, raw_size as f64/json_zstd.len() as f64);
        println!("  │ ② 模板+zstd:     {:>8} bytes ({:>5.1} KB) → {:>5.2}x           │", template_zstd.len(), template_zstd.len() as f64/1024.0, raw_size as f64/template_zstd.len() as f64);
        println!("  └────────────────────────────────────────────────────────────┘");
        println!();
        println!("  ┌─ 模板聚类质量 ─────────────────────────────────────────────┐");
        println!("  │ 模板总数:        {:>8}                                    │", batch.templates.len());
        println!("  │   其中单例:      {:>8} ({:>5.1}%)                         │", singletons, singletons as f64/batch.templates.len() as f64*100.0);
        println!("  │   最多实例/模板: {:>8}                                    │", max_instances);
        println!("  │   退化(全Param): {:>8}                                    │", templates_all_params);
        println!("  │ 平均参数/条:     {:>8.1}  (中位: {})                      │", avg_params, median_params);
        println!("  └────────────────────────────────────────────────────────────┘");
        println!();
        println!("  ┌─ 二进制中间产物拆解 (zstd 压缩前) ────────────────────────┐");
        println!("  │ 模板字典:        {:>8} bytes ({:>5.1} KB)                │", template_dict_size, template_dict_size as f64/1024.0);
        println!("  │   Literal 文本:  {:>8} bytes  (模板中固定文本)           │", total_literal_bytes);
        println!("  │ 记录部分预估:    {:>8} bytes                            │", bin_before_zstd.len() - template_dict_size);
        println!("  │   固定开销:      {:>8} bytes  ({}条 × 18B/条)           │", record_fixed_overhead, encoded.len());
        println!("  │   参数数据:      {:>8} bytes                            │", total_param_bytes);
        println!("  │ 中间产物总计:    {:>8} bytes ({:>5.1} KB)                │", bin_before_zstd.len(), bin_before_zstd.len() as f64/1024.0);
        println!("  │   vs 原始:       {:>8.1}%                               │", bin_before_zstd.len() as f64/raw_size as f64*100.0);
        println!("  └────────────────────────────────────────────────────────────┘");
        println!();
        println!("  ┌─ zstd 压缩效力对比 ───────────────────────────────────────┐");
        let bin_ret = template_zstd.len() as f64 / bin_before_zstd.len() as f64 * 100.0;
        let raw_ret = pure_zstd.len() as f64 / raw_size as f64 * 100.0;
        println!("  │ 原始文本 → zstd:  留存 {:.1}%  ({} → {} bytes)          │", raw_ret, raw_size, pure_zstd.len());
        println!("  │ 二进制   → zstd:  留存 {:.1}%  ({} → {} bytes)          │", bin_ret, bin_before_zstd.len(), template_zstd.len());
        println!("  └────────────────────────────────────────────────────────────┘");

        // 关键诊断
        println!();
        println!("  🔑 诊断结论:");
        let bin_ratio = bin_before_zstd.len() as f64 / raw_size as f64;
        if bin_ratio < 0.6 {
            println!("     ✅ 二进制编码有效：中间产物仅为原始的 {:.0}%", bin_ratio*100.0);
        } else if bin_ratio > 1.1 {
            println!("     ❌ 二进制编码膨胀：中间产物为原始的 {:.0}%", bin_ratio*100.0);
            if template_dict_size > raw_size / 3 {
                println!("        → 根因：模板字典过大 ({} bytes)，单例模板太多导致 Literal 重复存储", template_dict_size);
            }
            if record_fixed_overhead > raw_size / 2 {
                println!("        → 根因：记录固定开销过大 ({} bytes)，18B/条 × {}条", record_fixed_overhead, encoded.len());
            }
        } else {
            println!("     ⚠️  二进制编码体积与原始接近 ({:.0}%)", bin_ratio*100.0);
        }

        if bin_ret > raw_ret * 1.3 {
            println!("     ❌ zstd 对二进制压缩率({:.1}%留存)显著低于对文本({:.1}%留存)", bin_ret, raw_ret);
            println!("        → 二进制格式破坏了 zstd LZ77 的长距离模式匹配");
        } else if bin_ret < raw_ret * 0.7 {
            println!("     ✅ zstd 对二进制压缩优于文本");
        }
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }
}
