#!/bin/bash
# batch_evaluate.sh
# Batch evaluation script for MCP Pitfall Lab
# Evaluates multiple servers or challenges in sequence

set -e  # Exit on error

#===============================================================================
# Configuration
#===============================================================================

# Default values
MODE="pitfall"  # pitfall | source | both
OUTPUT_DIR="results/batch_evaluation"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
NUM_RUNS=3
STATIC_ONLY=false

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

Batch evaluation for MCP Pitfall Lab

OPTIONS:
    --mode MODE              Evaluation mode: pitfall, source, or both (default: pitfall)
    --servers-dir DIR        Directory containing server files (for pitfall mode)
    --challenges DIR         Directory containing challenge submissions (for source mode)
    --output-dir DIR         Output directory (default: results/batch_evaluation)
    --static-only            Only run static analysis (pitfall mode only)
    --num-runs N             Runs per submission for source mode (default: 3)
    -h, --help               Show this help message

EXAMPLES:
    # Batch evaluate all servers with Pitfall Lab
    $0 --mode pitfall --servers-dir user_servers/

    # Batch evaluate all challenges with Source Benchmark
    $0 --mode source --challenges environment/submissions/generated/

    # Static analysis only
    $0 --mode pitfall --servers-dir production_servers/ --static-only

    # Full evaluation (both modes)
    $0 --mode both --servers-dir servers/ --challenges submissions/
EOF
}

#===============================================================================
# Parse Arguments
#===============================================================================

SERVERS_DIR=""
CHALLENGES_DIR=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --servers-dir)
            SERVERS_DIR="$2"
            shift 2
            ;;
        --challenges)
            CHALLENGES_DIR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --static-only)
            STATIC_ONLY=true
            shift
            ;;
        --num-runs)
            NUM_RUNS="$2"
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

if [[ "$MODE" != "pitfall" && "$MODE" != "source" && "$MODE" != "both" ]]; then
    print_error "Invalid mode: $MODE"
    show_usage
    exit 1
fi

if [[ "$MODE" == "pitfall" || "$MODE" == "both" ]] && [[ -z "$SERVERS_DIR" ]]; then
    print_error "Pitfall mode requires --servers-dir"
    show_usage
    exit 1
fi

if [[ "$MODE" == "source" || "$MODE" == "both" ]] && [[ -z "$CHALLENGES_DIR" ]]; then
    print_error "Source mode requires --challenges"
    show_usage
    exit 1
fi

#===============================================================================
# Setup
#===============================================================================

BATCH_OUTPUT_DIR="$OUTPUT_DIR/$TIMESTAMP"
mkdir -p "$BATCH_OUTPUT_DIR"

SUMMARY_FILE="$BATCH_OUTPUT_DIR/batch_summary.json"
LOG_FILE="$BATCH_OUTPUT_DIR/batch_evaluation.log"

# Initialize summary
echo "{" > "$SUMMARY_FILE"
echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$SUMMARY_FILE"
echo "  \"mode\": \"$MODE\"," >> "$SUMMARY_FILE"
echo "  \"results\": {" >> "$SUMMARY_FILE"

print_banner "MCP Pitfall Lab - Batch Evaluation"
print_status "Mode: $MODE"
print_status "Output: $BATCH_OUTPUT_DIR"
print_status "Log: $LOG_FILE"

exec > >(tee -a "$LOG_FILE") 2>&1

#===============================================================================
# Pitfall Lab Batch Evaluation
#===============================================================================

evaluate_pitfall_lab() {
    print_banner "PITFALL LAB BATCH EVALUATION"
    
    if [[ ! -d "$SERVERS_DIR" ]]; then
        print_error "Servers directory not found: $SERVERS_DIR"
        return 1
    fi
    
    local server_count=0
    local success_count=0
    local high_severity_count=0
    
    print_status "Scanning for servers in: $SERVERS_DIR"
    
    # Find all Python server files
    while IFS= read -r -d '' server_file; do
        server_count=$((server_count + 1))
        
        server_name=$(basename "$server_file" .py)
        schema_file="${server_file%.py}_schema.json"
        
        print_status "[$server_count] Evaluating: $server_name"
        
        # Check if schema exists
        if [[ ! -f "$schema_file" ]]; then
            print_status "  ⚠️  Schema not found: $schema_file"
            print_status "  Attempting to use default schema location..."
            
            # Try alternative schema locations
            schema_dir=$(dirname "$server_file")
            schema_file="$schema_dir/schema.json"
            
            if [[ ! -f "$schema_file" ]]; then
                print_status "  ⚠️  No schema found, skipping..."
                continue
            fi
        fi
        
        # Run evaluation
        output_file="$BATCH_OUTPUT_DIR/pitfall_${server_name}.json"
        
        local eval_cmd="python evaluation/evaluate_pitfall_lab.py \
            --server-code \"$server_file\" \
            --server-schema \"$schema_file\" \
            --output \"$output_file\""
        
        if [[ "$STATIC_ONLY" == true ]]; then
            eval_cmd="$eval_cmd --static-only"
        fi
        
        if eval "$eval_cmd" >> "$LOG_FILE" 2>&1; then
            print_status "  ✓ Evaluation complete"
            success_count=$((success_count + 1))
            
            # Check for HIGH severity findings
            if command -v jq &> /dev/null; then
                high_findings=$(jq '.static_analysis.findings_by_severity.HIGH // 0' "$output_file")
                if [[ "$high_findings" -gt 0 ]]; then
                    print_status "  ⚠️  Found $high_findings HIGH severity issue(s)"
                    high_severity_count=$((high_severity_count + 1))
                fi
            fi
        else
            print_status "  ✗ Evaluation failed"
        fi
        
        echo ""
        
    done < <(find "$SERVERS_DIR" -name "*.py" -type f -print0)
    
    print_banner "PITFALL LAB SUMMARY"
    print_status "Total servers: $server_count"
    print_status "Successful evaluations: $success_count"
    print_status "Servers with HIGH severity issues: $high_severity_count"
    
    # Add to summary JSON
    cat >> "$SUMMARY_FILE" << EOF
    "pitfall_lab": {
      "total_servers": $server_count,
      "successful": $success_count,
      "high_severity_count": $high_severity_count
    }
EOF
}

#===============================================================================
# Source Benchmark Batch Evaluation
#===============================================================================

evaluate_source_benchmark() {
    print_banner "SOURCE BENCHMARK BATCH EVALUATION"
    
    if [[ ! -d "$CHALLENGES_DIR" ]]; then
        print_error "Challenges directory not found: $CHALLENGES_DIR"
        return 1
    fi
    
    local challenge_count=0
    local total_asr=0
    
    print_status "Scanning for challenges in: $CHALLENGES_DIR"
    
    # Find all challenge directories
    for challenge_dir in "$CHALLENGES_DIR"/*; do
        if [[ ! -d "$challenge_dir" ]]; then
            continue
        fi
        
        challenge_name=$(basename "$challenge_dir")
        challenge_count=$((challenge_count + 1))
        
        print_status "[$challenge_count] Evaluating challenge: $challenge_name"
        
        # Find latest submissions directory
        submissions_dir="$challenge_dir"
        if [[ -d "$challenge_dir/latest" ]]; then
            submissions_dir="$challenge_dir/latest"
        else
            # Find most recent timestamped directory
            latest_dir=$(find "$challenge_dir" -maxdepth 1 -type d -name "20*" | sort -r | head -n 1)
            if [[ -n "$latest_dir" ]]; then
                submissions_dir="$latest_dir"
            fi
        fi
        
        print_status "  Using submissions: $submissions_dir"
        
        # Run evaluation
        output_file="$BATCH_OUTPUT_DIR/source_${challenge_name}.json"
        
        if python evaluation/evaluate_source_asr.py \
            --challenge "$challenge_name" \
            --submissions-dir "$submissions_dir" \
            --num-runs "$NUM_RUNS" \
            --output "$output_file" >> "$LOG_FILE" 2>&1; then
            
            print_status "  ✓ Evaluation complete"
            
            # Extract ASR if jq is available
            if command -v jq &> /dev/null; then
                asr=$(jq -r '.overall_asr // 0' "$output_file")
                asr_pct=$(jq -r '.overall_asr_percentage // "N/A"' "$output_file")
                print_status "  ASR: $asr_pct"
                
                # Accumulate for average (crude, using bc if available)
                if command -v bc &> /dev/null; then
                    total_asr=$(echo "$total_asr + $asr" | bc)
                fi
            fi
        else
            print_status "  ✗ Evaluation failed"
        fi
        
        echo ""
    done
    
    # Calculate average ASR
    avg_asr="N/A"
    if [[ $challenge_count -gt 0 ]] && command -v bc &> /dev/null; then
        avg_asr=$(echo "scale=3; $total_asr / $challenge_count" | bc)
    fi
    
    print_banner "SOURCE BENCHMARK SUMMARY"
    print_status "Total challenges: $challenge_count"
    print_status "Average ASR: $avg_asr"
    
    # Add to summary JSON
    if [[ $challenge_count -eq 0 ]]; then
        echo "," >> "$SUMMARY_FILE"
    fi
    
    cat >> "$SUMMARY_FILE" << EOF
    "source_benchmark": {
      "total_challenges": $challenge_count,
      "average_asr": $avg_asr
    }
EOF
}

#===============================================================================
# Main Execution
#===============================================================================

START_TIME=$(date +%s)

if [[ "$MODE" == "pitfall" ]]; then
    evaluate_pitfall_lab
elif [[ "$MODE" == "source" ]]; then
    evaluate_source_benchmark
elif [[ "$MODE" == "both" ]]; then
    evaluate_pitfall_lab
    echo "," >> "$SUMMARY_FILE"
    evaluate_source_benchmark
fi

# Finalize summary JSON
echo "  }" >> "$SUMMARY_FILE"
echo "}" >> "$SUMMARY_FILE"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

print_banner "BATCH EVALUATION COMPLETE"
print_status "Total time: ${DURATION}s"
print_status "Results: $BATCH_OUTPUT_DIR"
print_status "Summary: $SUMMARY_FILE"
print_status "Log: $LOG_FILE"

echo ""
echo "To view summary:"
echo "  cat $SUMMARY_FILE"
echo ""
echo "To view detailed results:"
echo "  ls -lh $BATCH_OUTPUT_DIR/*.json"
echo ""

exit 0