//! Standalone WAF engine memory measurement.
//!
//! This is intentionally an example, not a unit test: it builds 2/10/100
//! site engines in the legacy per-site layout and with the shared WafBase,
//! using a counting allocator to report retained heap and peak heap.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use pingwaf_waf::rules::managed::default_managed_rules;
use pingwaf_waf::rules::signatures::SignatureEngine;
use pingwaf_waf::{
    CompiledRule, RuleAction, StackSet, WafEngine, WafEngineConfig, WafLevel,
};

struct CountingAllocator;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed)
                + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        old: Layout,
        new_size: usize,
    ) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, old, new_size) };
        if !new_ptr.is_null() {
            if new_size > old.size() {
                let delta = new_size - old.size();
                let now = CURRENT.fetch_add(delta, Ordering::Relaxed) + delta;
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                CURRENT.fetch_sub(old.size() - new_size, Ordering::Relaxed);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

fn config(custom_rule: bool) -> WafEngineConfig {
    let rules = if custom_rule {
        vec![CompiledRule::compile(
            "BENCH-001",
            "benchmark custom rule",
            r#"http.request.uri.path contains "/admin""#,
            RuleAction::Block,
            3,
            vec!["bench".to_string()],
        )
        .expect("benchmark expression must compile")]
    } else {
        Vec::new()
    };
    WafEngineConfig {
        level: WafLevel::Normal,
        stacks: StackSet::ALL,
        rules,
        ..Default::default()
    }
}

fn measure(sites: usize, shared: bool, custom_rule: bool) -> (usize, usize) {
    let before = CURRENT.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let engines: Vec<Arc<WafEngine>> = (0..sites)
        .map(|_| {
            let engine = if shared {
                WafEngine::new(&config(custom_rule))
            } else {
                WafEngine::new_unshared(&config(custom_rule))
            };
            Arc::new(engine)
        })
        .collect();
    let retained = CURRENT.load(Ordering::Relaxed).saturating_sub(before);
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before);
    // Keep the engines alive through the measurement.
    std::hint::black_box(&engines);
    drop(engines);
    (retained, peak)
}

fn measure_component<T>(build: impl FnOnce() -> T) -> (usize, usize) {
    let before = CURRENT.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let value = build();
    let retained = CURRENT.load(Ordering::Relaxed).saturating_sub(before);
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before);
    std::hint::black_box(&value);
    drop(value);
    (retained, peak)
}

fn main() {
    println!(
        "waf_scale_bench  engine_size={}",
        std::mem::size_of::<WafEngine>()
    );
    // Populate the shared registry once, then report its retained base. The
    // per-site shared rows below deliberately exclude this one-time cost.
    let base_before = CURRENT.load(Ordering::Relaxed);
    PEAK.store(base_before, Ordering::Relaxed);
    let base_engine = WafEngine::new(&config(false));
    let base_retained =
        CURRENT.load(Ordering::Relaxed).saturating_sub(base_before);
    let base_peak = PEAK.load(Ordering::Relaxed).saturating_sub(base_before);
    std::hint::black_box(&base_engine);
    drop(base_engine);
    println!(
        "shared_base_retained={base_retained} shared_base_peak={base_peak}"
    );
    let (sig_retained, sig_peak) = measure_component(|| {
        SignatureEngine::for_profile(WafLevel::Normal, StackSet::ALL)
    });
    let (managed_retained, managed_peak) =
        measure_component(|| default_managed_rules(WafLevel::Normal));
    println!("signature_retained={sig_retained} signature_peak={sig_peak}");
    println!("managed_retained={managed_retained} managed_peak={managed_peak}");
    println!(
        "{:<10} {:<6} {:<10} {:>14} {:>14} {:>14}",
        "mode",
        "sites",
        "custom",
        "total_retained",
        "total_peak",
        "incremental"
    );
    for custom in [false, true] {
        for sites in [2usize, 10, 100] {
            let (full, full_peak) = measure(sites, false, custom);
            let (shared, shared_peak) = measure(sites, true, custom);
            let full_inc = full / sites.max(1);
            let shared_inc = shared / sites.max(1);
            println!(
                "{:<10} {:<6} {:<10} {:>14} {:>14} {:>14}",
                "legacy", sites, custom, full, full_peak, full_inc
            );
            // Shared rows retain the base for the whole process; report the
            // one-time base plus this row so the table is comparable.
            println!(
                "{:<10} {:<6} {:<10} {:>14} {:>14} {:>14}",
                "shared",
                sites,
                custom,
                base_retained + shared,
                base_peak + shared_peak,
                shared_inc
            );
        }
    }
}
