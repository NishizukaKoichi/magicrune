# MagicRune

AI/外部生成コードを1回だけ安全に実行して結果を返す "唯一の実行ゲート"

## Features

- 100% Linux サンドボックス（Wasm フォールバック）
- 行動ログ → AI Grading → green / yellow / red
- 結果 JSON を CLI で出力、または JetStream で返信

## Quick Start

```bash
# Build
cargo build --release

# Run a safe example
./target/release/magicrune exec -f samples/ok.json

# Run with custom policy
./target/release/magicrune exec -f samples/ok.json --policy policies/default.policy.yml

# Start JetStream server
./target/release/magicrune serve --nats-url nats://localhost:4222
```

## CLI Usage

```bash
magicrune exec \
  -f request.json        # Required (SpellRequest)
  --policy policy.yml    # Optional (default.policy.yml)
  --timeout 15           # ≤60s
  --seed 42              # Deterministic RNG
  --out result.json      # Omit for stdout
  --strict               # Exit≠0 on schema mismatch
```

### Exit Codes

- 0: Green verdict
- 10: Yellow verdict  
- 20: Red verdict (quarantined)
- 1: Input schema mismatch
- 2: Output schema mismatch
- 3: Policy violation (not executed)
- 4: Internal error

## Architecture

```
spell-app/
└─ magicrune/
   ├─ src/
   │   ├─ main.rs         # CLI & JetStream consumer
   │   ├─ sandbox.rs      # Linux sandbox implementation
   │   ├─ grader.rs       # Risk scoring logic
   │   ├─ ledger.rs       # Storage abstraction
   │   └─ schema.rs       # Data structures
   ├─ policies/           # Security policies
   ├─ schemas/            # JSON schemas
   └─ samples/            # Example requests
```

## Security

The sandbox uses Linux namespaces and seccomp to isolate code execution:

- PID/NET/MNT/USER/IPC/UTS namespaces
- Read-only overlayfs with tmpfs for /tmp
- Strict seccomp allowlist
- cgroups v2 resource limits
- Network access denied by default

## License

See LICENSE file for details.