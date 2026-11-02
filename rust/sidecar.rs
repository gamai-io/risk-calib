// sidecar.rs — risk-calib hybrid: TOPLI Rust router sidecar (NDJSON preko stdio)
//
// Za razliku od router_rust (CLI po pozivu, plaća startup), ovaj proces se
// pokreće JEDNOM i drži se toplim. Protokol: jedna JSON linija po zahtjevu.
//
//   > {"id":1,"task":"Napravi ponudu ..."}
//   < {"id":1,"mode":"group","agents":[...],...}
//
// Posebne linije:
//   > {"cmd":"ping"}     -> {"pong":true}
//   > {"cmd":"quit"}     -> izlazi
//
// Python most (rust_bridge.py) ga zove i ima fallback na Python router.

use std::io::{self, BufRead, Write};

mod router; // logika podijeljena radi ponovne upotrebe

use serde_json::{json, Value};

fn main() {
    let r = router::Router::new();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(out, "{}", json!({"error": format!("bad json: {e}")}));
                let _ = out.flush();
                continue;
            }
        };

        // Kontrolne komande
        if let Some(cmd) = v.get("cmd").and_then(|c| c.as_str()) {
            match cmd {
                "ping" => {
                    let _ = writeln!(out, "{}", json!({"pong": true}));
                    let _ = out.flush();
                    continue;
                }
                "batch" => {
                    // Batch: {"cmd":"batch","tasks":[...]} -> {"results":[...]}
                    let mut results: Vec<Value> = Vec::new();
                    if let Some(arr) = v.get("tasks").and_then(|t| t.as_array()) {
                        for t in arr {
                            let task = t.as_str().unwrap_or("");
                            results.push(r.route_with(task, None, None));
                        }
                    }
                    let _ = writeln!(out, "{}", json!({"results": results}));
                    let _ = out.flush();
                    continue;
                }
                "quit" => break,
                _ => {
                    let _ = writeln!(out, "{}", json!({"error": format!("unknown cmd: {cmd}")}));
                    let _ = out.flush();
                    continue;
                }
            }
        }

        let id = v.get("id").cloned().unwrap_or(Value::Null);
        let task = v.get("task").and_then(|t| t.as_str()).unwrap_or("");
        let hint = v.get("domain_hint").and_then(|t| t.as_str());
        let risk = v.get("risk").and_then(|t| t.as_f64());

        let mut res = r.route_with(task, hint, risk);
        // Upiši id nazad (ako je poslan)
        if let Some(obj) = res.as_object_mut() {
            obj.insert("id".to_string(), id);
        }
        let _ = writeln!(out, "{}", res);
        let _ = out.flush();
    }
}
