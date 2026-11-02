# risk-calib

Deterministic, test-driven risk calibration for agent routers. Small scores,
explicit tiers, and reference implementations in six languages.

## Model

- **T1 — catastrophic (0.90):** `rm -rf /`, `mkfs`, `dd if=… of=/dev/…`,
  `drop table/database`, `truncate table`, `shutdown`, `reboot`,
  “delete everything”, “delete database/disk”.
- **T2 — high (0.70):** delete a file/folder/log, `rm`, `drop`, `truncate`,
  root access, “stop server”, `killall`, `pkill -9`, `chmod 777`, `chown -R`.
- **Base:** `min(0.75, hits × 0.35)`.
- **Sensitive domains:** finance +0.25, accounting +0.20, legal +0.30, HR +0.15.
- **Finance + transfer:** +0.15.
- **Hard block:** risk ≥ 0.85.

The model is intentionally small and inspectable. It is not a substitute for
authorization, sandboxing, or human approval.

## Implementations

| Language | Path | Notes |
|---|---|---|
| Python | `python/router.py` | reference, `Router(risk_model="v2")` |
| Rust | `rust/` | CLI + sidecar |
| Go | `go/` | native CLI |
| LuaJIT | `lua/router.lua` | native CLI |
| Rust/WASM | `wasm/` | `wasm32-wasip1` library |
| Odin | `odin/router_odin.odin` | native CLI |

All six reproduce the same 31-case fixture: **0 field differences**.
Python ↔ Rust/Go/LuaJIT/WASM/Odin v2: **PASS 0**.

## Quick start (Python)

```bash
python3 - <<'PY'
import sys; sys.path.insert(0, "python")
from router import Router
r = Router(risk_model="v2")
print(r.route("rm -rf /"))
PY
```

```bash
python3 -m unittest discover -s tests -t .
```

## Fixtures

`fixtures/inputs.json` — 31 tasks.
`fixtures/expected.json` — legacy v1 expected output.
`fixtures/expected_risk_v2.json` — v2 expected output.

## Measured throughput

On a Linux x86_64 host, 31,000 tasks (N=1000):

| Implementation | tasks/s |
|---|---:|
| Rust CLI | ~104,000 |
| Rust sidecar batch | ~53,000 |
| Odin | ~31,800 |
| LuaJIT | ~24,600 |
| WASM (wasmtime-py) | ~17,300 |
| Go | ~14,000 |
| Python | ~9,400 |

These are local measurements on one host, not portable guarantees.

## Safety

- No network calls.
- No execution of analysed input.
- The router returns a score and a rationale; callers decide whether to block.
- Test fixtures are synthetic and contain no customer data.

## License

MIT.
