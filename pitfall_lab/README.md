# Pitfall Lab - MCP Security Testing Framework

A comprehensive framework for automated MCP (Model Context Protocol) security testing and benchmark quality assessment

---

## 🎯 Project Overview

Pitfall Lab provides two major capabilities:

### Phase 1: Core Mapping
**Automated security testing pipeline**
- Run MCP challenges programmatically
- Parse execution traces and results
- Extract structured attack path data
- Analyze tool calls and agent behavior
- Generate formatted reports (Markdown/JSON)

### Phase 2: Scenario Evaluation  
**Benchmark quality assessment**
- Evaluate challenge scenarios across 5 dimensions
- Measure attack surface, difficulty, coverage, discriminability, realism
- Compare scenarios to identify strengths/weaknesses
- Generate empirical metrics from historical runs

---

## 📦 What's Included

### Core Module Files (9 files)

Place in `pitfall_lab/` directory:

| File | Purpose |
|------|---------|
| `__init__.py` | Package initialization & exports |
| `__main__.py` | CLI entry point | 
| `runner.py` | Bridge to arena execution engine | 
| `parser.py` | Parse trace.jsonl and report.json |
| `reporter.py` | Generate Markdown/HTML/JSON reports | 
| `cli.py` | Command-line interface (Phase 1+2) | 
| `evaluator.py` | Scenario evaluation logic |
| `eval_cli.py` | Evaluation CLI commands |
| `README.md` | Module documentation | 

---

## 🚀 Quick Start

**Verify Main File:**
   ```bash
   python -m pitfall_lab --help
   ```

### Basic Usage

**Phase 1 - Run & Analyze:**
```bash
# Run a challenge
python -m pitfall_lab run \
    --challenge emailsystem \
    --attack tool_poisoning \
    --submission malicious_server.py

# Analyze results
python -m pitfall_lab analyze --run-id <run_id> --verbose

# Generate report
python -m pitfall_lab report --run-id <run_id> --format json
```

**Phase 2 - Evaluate Scenarios:**
```bash
# Evaluate single scenario
python -m pitfall_lab eval-scenario --challenge emailsystem

# Compare all scenarios
python -m pitfall_lab compare-scenarios --detailed

# Export evaluation data
python -m pitfall_lab eval-scenario \
    --challenge emailsystem \
    --runs-dir environment/runs \
    --export evaluation.json
```

---

## 📈 Evaluation Metrics (Phase 2)

### Overall Quality Score
Weighted average: Coverage (30%) + Discriminability (25%) + Difficulty (20%) + Realism (15%) + Attack Surface (10%)

### Per-Dimension Details

**Attack Surface:**
```
score = sensitive_tools / total_tools
```

**Coverage:**
```
score = tested_categories / total_categories

Categories tested:
- Data exfiltration
- Privilege escalation
- Tool poisoning
- Prompt injection
- Multimodal attacks
```

**Discriminability:**
```
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
F1 Score = 2 * (Precision × Recall) / (Precision + Recall)
```

**Difficulty:**
- Multi-step required: +0.3
- Reasoning needed: +0.3
- Auth checks present: +0.2
- Input validation: +0.2

**Realism:**
- Based on real system: +0.25
- Standard protocols: +0.25
- Realistic prompts: +0.25
- Realistic data: +0.25

---


### 4. Batch Testing

Test multiple submissions:
```python
submissions = ["v1.py", "v2.py", "v3.py"]

for sub in submissions:
    result = run_challenge(
        challenge_id="emailsystem",
        attack="tool_poisoning",
        submission=sub
    )
    print(f"{sub}: {'✓' if result['ok'] else '✗'}")
```

---


## 🔧 Commands Reference

### Phase 1 Commands

```bash
# Run challenge
python -m pitfall_lab run \
    --challenge <id> \
    --attack <attack> \
    --submission <path>

# Analyze results
python -m pitfall_lab analyze \
    --run-id <id> \
    [--verbose] \
    [--export <file.json>]

# Generate report
python -m pitfall_lab report \
    --run-id <id> \
    [--format markdown|html|json] \
    [--output <file>]
```

### Phase 2 Commands

```bash
# Evaluate scenario
python -m pitfall_lab eval-scenario \
    --challenge <id> \
    [--runs-dir <path>] \
    [--ground-truth <labels.json>] \
    [--export <file.json>]

# Compare scenarios
python -m pitfall_lab compare-scenarios \
    [--challenges <id1,id2,...>] \
    [--detailed] \
    [--export <file.json>]
```

---

## ✅ Requirements

- **Python:** 3.10 or higher
- **Dependencies:** None additional (uses existing arena dependencies)
- **Environment:** Existing `environment/arena/` infrastructure
- **OS:** Any (tested on Linux, macOS, Windows)

---

## 🆘 Troubleshooting

### Common Issues

**ImportError: No module named 'environment'**
- Run from project root where `environment/` exists
- Verify: `ls environment/arena/`

**ImportError: No module named 'pitfall_lab'**
- Check files are in `pitfall_lab/` directory
- Verify: `ls pitfall_lab/*.py` shows 8 files

**Command not found**
- Use: `python -m pitfall_lab` not just `pitfall_lab`
- Check Python version: `python --version` (need 3.10+)

