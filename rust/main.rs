// main.rs — risk-calib hybrid: Rust router CLI (tanki omotač nad router.rs modulom).
// Isti format kao Go router_go/main.go.
//   router_rust -in fixtures/inputs.json
//   router_rust -bench -n 10000 -in fixtures/inputs.json

mod router;

use std::io::Read;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut in_file: Option<String> = None;
    let mut bench = false;
    let mut n: usize = 10000;

    let mut i = 1usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-in" || a == "--in" {
            i += 1;
            if i < args.len() {
                in_file = Some(args[i].clone());
            }
        } else if let Some(v) = a.strip_prefix("-in=").or_else(|| a.strip_prefix("--in=")) {
            in_file = Some(v.to_string());
        } else if a == "-bench" || a == "--bench" {
            bench = true;
        } else if a == "-n" || a == "--n" {
            i += 1;
            if i < args.len() {
                n = args[i].parse().unwrap_or(10000);
            }
        } else if let Some(v) = a.strip_prefix("-n=").or_else(|| a.strip_prefix("--n=")) {
            n = v.parse().unwrap_or(10000);
        }
        i += 1;
    }

    let raw = match &in_file {
        Some(f) => std::fs::read_to_string(f).unwrap_or_else(|e| {
            eprintln!("greska citanja: {}", e);
            std::process::exit(1);
        }),
        None => {
            let mut s = String::new();
            let _ = std::io::stdin().read_to_string(&mut s);
            s
        }
    };

    let tasks: Vec<String> = {
        let trimmed = raw.trim();
        if in_file.is_some() || trimmed.starts_with('[') {
            serde_json::from_str(trimmed).unwrap_or_else(|e| {
                eprintln!("greska JSON: {}", e);
                std::process::exit(1);
            })
        } else {
            trimmed.split('\n').map(|s| s.to_string()).collect()
        }
    };

    let r = router::Router::new();

    if bench {
        let start = Instant::now();
        let mut last: Vec<router::RouteResult> = Vec::new();
        for _ in 0..n {
            last = Vec::with_capacity(tasks.len());
            for t in tasks.iter() {
                last.push(r.route(t));
            }
        }
        let el = start.elapsed().as_secs_f64();
        let total = n * tasks.len();
        eprintln!(
            "BENCH: {} upita u {:.4}s = {:.2} us/upit ({:.0} upita/s)",
            total,
            el,
            el * 1e6 / total as f64,
            total as f64 / el
        );
        let out = serde_json::to_string_pretty(&last).expect("json");
        println!("{}", out);
        return;
    }

    let results: Vec<router::RouteResult> = tasks.iter().map(|t| r.route(t)).collect();
    let out = serde_json::to_string_pretty(&results).expect("json");
    println!("{}", out);
}
