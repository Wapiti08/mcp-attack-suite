#!/bin/bash
# multi_model_batch_evaluate.sh
# Multi-model batch evaluation script for MCP Attack Suite
# Tests multiple models across all scenarios and generates comparison tables

set -e  # Exit on error

#===============================================================================
# Configuration
#===============================================================================

# Model configurations
# Format: "model_id:display_name:tier"
declare -a MODELS=(
    # Anthropic Claude models
    "claude-sonnet-4-20250514:Claude Sonnet 4:flagship"
    "claude-3-5-sonnet-20241022:Claude 3.5 Sonnet:strong"
    "claude-3-5-haiku-20241022:Claude 3.5 Haiku:fast"
    "claude-3-haiku-20240307:Claude 3 Haiku:legacy"
    
    # OpenAI GPT models
    "gpt-4o:GPT-4o:flagship"
    "gpt-4o-mini:GPT-4o mini:fast"
    "gpt-4-turbo:GPT-4 Turbo:strong"
    
    # Google Gemini models
    "gemini-2.0-flash-exp:Gemini 2.0 Flash:flagship"
    "gemini-1.5-pro:Gemini 1.5 Pro:strong"
    
    # Alibaba Qwen models
    "qwen-max:Qwen Max:flagship"
    "qwen-plus:Qwen Plus:strong"
    "qwen-turbo:Qwen Turbo:fast"
)

# Default attack types to test
declare -a ATTACK_TYPES=(
    "tool_poisoning"
    "multimodal_attack"
    "puppet"
)

# Default challenges to test
declare -a CHALLENGES=(
    "emailsystem"
    "documentsystem"
    "ETHPriceServer"
)

# Default values
OUTPUT_DIR="results/multi_model_batch"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
NUM_RUNS=3
PARALLEL_JOBS=1
MODELS_FILTER=""
CHALLENGES_FILTER=""
ATTACKS_FILTER=""

#===============================================================================
# Functions
#===============================================================================

print_banner() {
    echo ""
    echo "========================================================================"
    echo "$1"
    echo "========================================================================"
    echo ""
}

print_status() {
    echo "[$(date +"%H:%M:%S")] $1"
}

print_error() {
    echo "[ERROR] $1" >&2
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Multi-model batch evaluation for MCP Attack Suite

OPTIONS:
    --submissions-dir DIR    Base directory for attack submissions (required)
    --output-dir DIR         Output directory (default: results/multi_model_batch)
    --num-runs N             Runs per submission (default: 3)
    --parallel N             Number of parallel jobs (default: 1)
    --models LIST            Comma-separated model IDs to test (default: all)
    --challenges LIST        Comma-separated challenges to test (default: all)
    --attacks LIST           Comma-separated attack types (default: all)
    -h, --help               Show this help message

AVAILABLE MODELS:
    Anthropic Claude:
      claude-sonnet-4-20250514        (Claude Sonnet 4 - Flagship)
      claude-3-5-sonnet-20241022      (Claude 3.5 Sonnet - Strong)
      claude-3-5-haiku-20241022       (Claude 3.5 Haiku - Fast)
      claude-3-haiku-20240307         (Claude 3 Haiku - Legacy)
    
    OpenAI GPT:
      gpt-4o                          (GPT-4o - Flagship)
      gpt-4o-mini                     (GPT-4o mini - Fast)
      gpt-4-turbo                     (GPT-4 Turbo - Strong)
    
    Google Gemini:
      gemini-2.0-flash-exp            (Gemini 2.0 Flash - Flagship)
      gemini-1.5-pro                  (Gemini 1.5 Pro - Strong)
    
    Alibaba Qwen:
      qwen-max                        (Qwen Max - Flagship)
      qwen-plus                       (Qwen Plus - Strong)
      qwen-turbo                      (Qwen Turbo - Fast)
    
    Total: 12 models across 4 providers

EXAMPLES:
    # Full evaluation across all models and challenges
    $0 --submissions-dir environment/submissions/generated

    # Test only flagship models on emailsystem
    $0 --submissions-dir submissions/ \\
       --models claude-sonnet-4-20250514 \\
       --challenges emailsystem

    # Fast iteration with parallel execution
    $0 --submissions-dir submissions/ \\
       --parallel 4 \\
       --num-runs 1

    # Test specific attack types
    $0 --submissions-dir submissions/ \\
       --attacks tool_poisoning,multimodal_attack
EOF
}

#===============================================================================
# Parse Arguments
#===============================================================================

SUBMISSIONS_DIR=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --submissions-dir)
            SUBMISSIONS_DIR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --num-runs)
            NUM_RUNS="$2"
            shift 2
            ;;
        --parallel)
            PARALLEL_JOBS="$2"
            shift 2
            ;;
        --models)
            MODELS_FILTER="$2"
            shift 2
            ;;
        --challenges)
            CHALLENGES_FILTER="$2"
            shift 2
            ;;
        --attacks)
            ATTACKS_FILTER="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

#===============================================================================
# Validation
#===============================================================================

if [[ -z "$SUBMISSIONS_DIR" ]]; then
    print_error "Missing required argument: --submissions-dir"
    show_usage
    exit 1
fi

if [[ ! -d "$SUBMISSIONS_DIR" ]]; then
    print_error "Submissions directory not found: $SUBMISSIONS_DIR"
    exit 1
fi

#===============================================================================
# Filter configurations based on user input
#===============================================================================

if [[ -n "$MODELS_FILTER" ]]; then
    IFS=',' read -ra MODEL_IDS <<< "$MODELS_FILTER"
    FILTERED_MODELS=()
    for model_config in "${MODELS[@]}"; do
        model_id="${model_config%%:*}"
        for filter_id in "${MODEL_IDS[@]}"; do
            if [[ "$model_id" == "$filter_id" ]]; then
                FILTERED_MODELS+=("$model_config")
                break
            fi
        done
    done
    MODELS=("${FILTERED_MODELS[@]}")
fi

if [[ -n "$CHALLENGES_FILTER" ]]; then
    IFS=',' read -ra CHALLENGES <<< "$CHALLENGES_FILTER"
fi

if [[ -n "$ATTACKS_FILTER" ]]; then
    IFS=',' read -ra ATTACK_TYPES <<< "$ATTACKS_FILTER"
fi

#===============================================================================
# Setup
#===============================================================================

BATCH_OUTPUT_DIR="$OUTPUT_DIR/$TIMESTAMP"
mkdir -p "$BATCH_OUTPUT_DIR"
mkdir -p "$BATCH_OUTPUT_DIR/raw_results"
mkdir -p "$BATCH_OUTPUT_DIR/tables"

LOG_FILE="$BATCH_OUTPUT_DIR/evaluation.log"
RESULTS_MATRIX="$BATCH_OUTPUT_DIR/results_matrix.json"

# Initialize results matrix
echo "{" > "$RESULTS_MATRIX"
echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$RESULTS_MATRIX"
echo "  \"num_runs\": $NUM_RUNS," >> "$RESULTS_MATRIX"
echo "  \"models\": [" >> "$RESULTS_MATRIX"
for i in "${!MODELS[@]}"; do
    model_config="${MODELS[$i]}"
    IFS=':' read -r model_id display_name tier <<< "$model_config"
    echo "    {\"id\": \"$model_id\", \"name\": \"$display_name\", \"tier\": \"$tier\"}" >> "$RESULTS_MATRIX"
    if [[ $i -lt $((${#MODELS[@]} - 1)) ]]; then
        echo "," >> "$RESULTS_MATRIX"
    fi
done
echo "  ]," >> "$RESULTS_MATRIX"
echo "  \"challenges\": $(printf '%s\n' "${CHALLENGES[@]}" | jq -R . | jq -s .)," >> "$RESULTS_MATRIX"
echo "  \"attack_types\": $(printf '%s\n' "${ATTACK_TYPES[@]}" | jq -R . | jq -s .)," >> "$RESULTS_MATRIX"
echo "  \"results\": {" >> "$RESULTS_MATRIX"

print_banner "MCP ATTACK SUITE - MULTI-MODEL BATCH EVALUATION"
print_status "Submissions: $SUBMISSIONS_DIR"
print_status "Output: $BATCH_OUTPUT_DIR"
print_status "Models: ${#MODELS[@]}"
print_status "Challenges: ${#CHALLENGES[@]}"
print_status "Attack Types: ${#ATTACK_TYPES[@]}"
print_status "Runs per submission: $NUM_RUNS"
print_status "Parallel jobs: $PARALLEL_JOBS"

exec > >(tee -a "$LOG_FILE") 2>&1

#===============================================================================
# Run Evaluations
#===============================================================================

run_evaluation() {
    local model_id="$1"
    local model_name="$2"
    local challenge="$3"
    local output_key="${model_id}__${challenge}"
    local output_file="$BATCH_OUTPUT_DIR/raw_results/${output_key}.json"
    
    print_status "Evaluating: $model_name on $challenge"
    
    # Find submissions directory for this challenge
    local submissions_dir="$SUBMISSIONS_DIR/$challenge"
    if [[ -d "$SUBMISSIONS_DIR/$challenge/latest" ]]; then
        submissions_dir="$SUBMISSIONS_DIR/$challenge/latest"
    fi
    
    if [[ ! -d "$submissions_dir" ]]; then
        print_error "Submissions not found: $submissions_dir"
        return 1
    fi
    
    # Run evaluation
    if python evaluation/evaluate_source_asr.py \
        --challenge "$challenge" \
        --submissions-dir "$submissions_dir" \
        --model "$model_id" \
        --num-runs "$NUM_RUNS" \
        --attack-types "${ATTACK_TYPES[@]}" \
        --output "$output_file" 2>&1 | grep -v "^$"; then
        
        print_status "✓ Completed: $model_name on $challenge"
        return 0
    else
        print_error "✗ Failed: $model_name on $challenge"
        return 1
    fi
}

# Track total evaluations
total_evals=$((${#MODELS[@]} * ${#CHALLENGES[@]}))
completed=0

print_banner "RUNNING EVALUATIONS"
print_status "Total evaluations to run: $total_evals"

# Export functions for parallel execution
export -f run_evaluation
export -f print_status
export -f print_error

# Build job list
job_list="$BATCH_OUTPUT_DIR/job_list.txt"
> "$job_list"

for model_config in "${MODELS[@]}"; do
    IFS=':' read -r model_id model_name tier <<< "$model_config"
    for challenge in "${CHALLENGES[@]}"; do
        echo "$model_id|$model_name|$challenge" >> "$job_list"
    done
done

# Run evaluations (with optional parallelization)
if command -v parallel &> /dev/null && [[ $PARALLEL_JOBS -gt 1 ]]; then
    print_status "Using GNU parallel with $PARALLEL_JOBS jobs"
    
    cat "$job_list" | parallel -j "$PARALLEL_JOBS" --colsep '|' \
        "run_evaluation {1} {2} {3}"
else
    # Sequential execution
    while IFS='|' read -r model_id model_name challenge; do
        run_evaluation "$model_id" "$model_name" "$challenge"
        completed=$((completed + 1))
        print_status "Progress: $completed/$total_evals"
    done < "$job_list"
fi

#===============================================================================
# Aggregate Results
#===============================================================================

print_banner "AGGREGATING RESULTS"

# Create Python script to aggregate results
cat > "$BATCH_OUTPUT_DIR/aggregate_results.py" << 'PYTHON_EOF'
#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from collections import defaultdict

def aggregate_results(results_dir, output_file):
    """Aggregate all evaluation results into a matrix"""
    results_dir = Path(results_dir)
    
    # Structure: {challenge: {model: {attack_type: asr}}}
    matrix = defaultdict(lambda: defaultdict(dict))
    
    # Load all result files
    for result_file in results_dir.glob("*.json"):
        try:
            with open(result_file) as f:
                data = json.load(f)
            
            # Parse filename: model_id__challenge.json
            parts = result_file.stem.split("__")
            if len(parts) != 2:
                continue
                
            model_id, challenge = parts
            
            # Extract ASR for each attack type
            if "by_attack_type" in data:
                for attack_type, attack_data in data["by_attack_type"].items():
                    asr = attack_data.get("asr", 0.0)
                    total = attack_data.get("total_attempts", 0)
                    successful = attack_data.get("successful_attacks", 0)
                    
                    matrix[challenge][model_id][attack_type] = {
                        "asr": asr,
                        "asr_percentage": f"{asr:.1%}",
                        "total_attempts": total,
                        "successful_attacks": successful
                    }
            
            # Overall ASR
            overall_asr = data.get("overall_asr", 0.0)
            matrix[challenge][model_id]["overall"] = {
                "asr": overall_asr,
                "asr_percentage": f"{overall_asr:.1%}",
                "total_attempts": data.get("total_attempts", 0),
                "successful_attacks": data.get("total_successful", 0)
            }
            
        except Exception as e:
            print(f"Error processing {result_file}: {e}", file=sys.stderr)
    
    # Convert to regular dict for JSON serialization
    matrix = {k: {k2: dict(v2) for k2, v2 in v.items()} 
              for k, v in matrix.items()}
    
    # Save aggregated results
    with open(output_file, 'w') as f:
        json.dump(matrix, f, indent=2)
    
    return matrix

if __name__ == "__main__":
    results_dir = sys.argv[1]
    output_file = sys.argv[2]
    aggregate_results(results_dir, output_file)
    print(f"Aggregated results saved to {output_file}")
PYTHON_EOF

chmod +x "$BATCH_OUTPUT_DIR/aggregate_results.py"

# Run aggregation
aggregated_results="$BATCH_OUTPUT_DIR/aggregated_results.json"
python3 "$BATCH_OUTPUT_DIR/aggregate_results.py" \
    "$BATCH_OUTPUT_DIR/raw_results" \
    "$aggregated_results"

#===============================================================================
# Generate Tables
#===============================================================================

print_banner "GENERATING TABLES"

# Create Python script to generate tables
cat > "$BATCH_OUTPUT_DIR/generate_tables.py" << 'PYTHON_EOF'
#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from typing import Dict, List

def load_data(aggregated_file: Path, matrix_file: Path):
    """Load aggregated results and metadata"""
    with open(aggregated_file) as f:
        results = json.load(f)
    
    with open(matrix_file) as f:
        metadata = json.load(f)
    
    return results, metadata

def generate_markdown_table(results: Dict, metadata: Dict, output_dir: Path):
    """Generate markdown comparison tables"""
    
    models = {m['id']: m for m in metadata['models']}
    challenges = metadata['challenges']
    attack_types = metadata['attack_types']
    
    # Overall ASR table
    with open(output_dir / "overall_asr_table.md", 'w') as f:
        f.write("# Overall ASR by Model and Challenge\n\n")
        
        # Header
        f.write("| Model | " + " | ".join(challenges) + " | Average |\n")
        f.write("|" + "---|" * (len(challenges) + 2) + "\n")
        
        # Rows
        for model_id, model_info in models.items():
            row = [model_info['name']]
            model_asrs = []
            
            for challenge in challenges:
                if challenge in results and model_id in results[challenge]:
                    asr_data = results[challenge][model_id].get('overall', {})
                    asr_pct = asr_data.get('asr_percentage', 'N/A')
                    row.append(asr_pct)
                    if asr_pct != 'N/A':
                        model_asrs.append(asr_data.get('asr', 0.0))
                else:
                    row.append('N/A')
            
            # Average
            if model_asrs:
                avg_asr = sum(model_asrs) / len(model_asrs)
                row.append(f"{avg_asr:.1%}")
            else:
                row.append('N/A')
            
            f.write("| " + " | ".join(row) + " |\n")
    
    # Per-attack-type tables
    for attack_type in attack_types:
        with open(output_dir / f"{attack_type}_table.md", 'w') as f:
            f.write(f"# {attack_type.replace('_', ' ').title()} ASR by Model and Challenge\n\n")
            
            # Header
            f.write("| Model | " + " | ".join(challenges) + " | Average |\n")
            f.write("|" + "---|" * (len(challenges) + 2) + "\n")
            
            # Rows
            for model_id, model_info in models.items():
                row = [model_info['name']]
                model_asrs = []
                
                for challenge in challenges:
                    if challenge in results and model_id in results[challenge]:
                        attack_data = results[challenge][model_id].get(attack_type, {})
                        asr_pct = attack_data.get('asr_percentage', 'N/A')
                        row.append(asr_pct)
                        if asr_pct != 'N/A':
                            model_asrs.append(attack_data.get('asr', 0.0))
                    else:
                        row.append('N/A')
                
                # Average
                if model_asrs:
                    avg_asr = sum(model_asrs) / len(model_asrs)
                    row.append(f"{avg_asr:.1%}")
                else:
                    row.append('N/A')
                
                f.write("| " + " | ".join(row) + " |\n")

def generate_csv_table(results: Dict, metadata: Dict, output_dir: Path):
    """Generate CSV tables for easy import to spreadsheets"""
    import csv
    
    models = {m['id']: m for m in metadata['models']}
    challenges = metadata['challenges']
    attack_types = metadata['attack_types']
    
    # Overall ASR CSV
    with open(output_dir / "overall_asr_table.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Header
        writer.writerow(['Model', 'Model Tier'] + challenges + ['Average ASR', 'Total Attempts', 'Total Successful'])
        
        # Rows
        for model_id, model_info in models.items():
            row = [model_info['name'], model_info['tier']]
            model_asrs = []
            total_attempts = 0
            total_successful = 0
            
            for challenge in challenges:
                if challenge in results and model_id in results[challenge]:
                    overall_data = results[challenge][model_id].get('overall', {})
                    asr = overall_data.get('asr', 0.0)
                    row.append(f"{asr:.3f}")
                    model_asrs.append(asr)
                    total_attempts += overall_data.get('total_attempts', 0)
                    total_successful += overall_data.get('successful_attacks', 0)
                else:
                    row.append('')
            
            # Average
            if model_asrs:
                avg_asr = sum(model_asrs) / len(model_asrs)
                row.append(f"{avg_asr:.3f}")
            else:
                row.append('')
            
            row.append(str(total_attempts))
            row.append(str(total_successful))
            
            writer.writerow(row)
    
    # Per-attack-type CSV
    for attack_type in attack_types:
        with open(output_dir / f"{attack_type}_table.csv", 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['Model'] + challenges + ['Average ASR'])
            
            # Rows
            for model_id, model_info in models.items():
                row = [model_info['name']]
                model_asrs = []
                
                for challenge in challenges:
                    if challenge in results and model_id in results[challenge]:
                        attack_data = results[challenge][model_id].get(attack_type, {})
                        asr = attack_data.get('asr', 0.0)
                        row.append(f"{asr:.3f}")
                        model_asrs.append(asr)
                    else:
                        row.append('')
                
                # Average
                if model_asrs:
                    avg_asr = sum(model_asrs) / len(model_asrs)
                    row.append(f"{avg_asr:.3f}")
                else:
                    row.append('')
                
                writer.writerow(row)

def generate_summary(results: Dict, metadata: Dict, output_file: Path):
    """Generate a human-readable summary"""
    
    models = {m['id']: m for m in metadata['models']}
    challenges = metadata['challenges']
    
    with open(output_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("MULTI-MODEL EVALUATION SUMMARY\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Timestamp: {metadata['timestamp']}\n")
        f.write(f"Runs per submission: {metadata['num_runs']}\n")
        f.write(f"Models tested: {len(models)}\n")
        f.write(f"Challenges tested: {len(challenges)}\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("OVERALL RESULTS\n")
        f.write("-" * 80 + "\n\n")
        
        for model_id, model_info in models.items():
            f.write(f"\n{model_info['name']} ({model_info['tier']})\n")
            f.write("-" * 40 + "\n")
            
            for challenge in challenges:
                if challenge in results and model_id in results[challenge]:
                    overall = results[challenge][model_id].get('overall', {})
                    f.write(f"  {challenge:20s}: {overall.get('asr_percentage', 'N/A'):>6s}  ")
                    f.write(f"({overall.get('successful_attacks', 0)}/{overall.get('total_attempts', 0)} successful)\n")
                else:
                    f.write(f"  {challenge:20s}: N/A\n")

if __name__ == "__main__":
    aggregated_file = Path(sys.argv[1])
    matrix_file = Path(sys.argv[2])
    output_dir = Path(sys.argv[3])
    
    results, metadata = load_data(aggregated_file, matrix_file)
    
    print("Generating markdown tables...")
    generate_markdown_table(results, metadata, output_dir)
    
    print("Generating CSV tables...")
    generate_csv_table(results, metadata, output_dir)
    
    print("Generating summary...")
    generate_summary(results, metadata, output_dir / "summary.txt")
    
    print(f"\nTables generated in {output_dir}")
PYTHON_EOF

chmod +x "$BATCH_OUTPUT_DIR/generate_tables.py"

# Run table generation
python3 "$BATCH_OUTPUT_DIR/generate_tables.py" \
    "$aggregated_results" \
    "$RESULTS_MATRIX" \
    "$BATCH_OUTPUT_DIR/tables"

#===============================================================================
# Summary
#===============================================================================

print_banner "EVALUATION COMPLETE"

cat "$BATCH_OUTPUT_DIR/tables/summary.txt"

echo ""
echo "Generated outputs:"
echo "  Raw results:       $BATCH_OUTPUT_DIR/raw_results/"
echo "  Aggregated data:   $aggregated_results"
echo "  Markdown tables:   $BATCH_OUTPUT_DIR/tables/*.md"
echo "  CSV tables:        $BATCH_OUTPUT_DIR/tables/*.csv"
echo "  Summary:           $BATCH_OUTPUT_DIR/tables/summary.txt"
echo "  Full log:          $LOG_FILE"
echo ""

exit 0