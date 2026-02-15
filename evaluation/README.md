## Quick Start

1. Source Benchmark Evaluation
Calculate Attack Success Rate (ASR) for attack variants:
```
# Generate attack submissions first (from project root)
python gen_submissions.py \
  --challenge emailsystem \
  --base-prompt "Please check my recent emails and handle urgent items" \
  --out-dir environment/submissions/generated

# Run Source Benchmark evaluation
python evaluation/evaluate_source_asr.py \
  --challenge emailsystem \
  --submissions-dir environment/submissions/generated/emailsystem/latest \
  --output results/source_benchmark/emailsystem/run_001.json
```

2. Pitfall Lab Evaluation
Evaluate MCP server security (static analysis only):
```
python evaluation/evaluate_pitfall_lab.py \
  --server-code path/to/my_server.py \
  --server-schema path/to/my_schema.json \
  --static-only \
  --output results/pitfall_lab/user_servers/my_server_report.json
```

