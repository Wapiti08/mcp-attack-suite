#!/usr/bin/env python3
"""
multi_model_evaluator.py
Python-based multi-model batch evaluator with YAML configuration support

Features:
- Read model configurations from YAML
- Parallel execution support
- Progress tracking
- Automatic table generation
- Cost estimation
"""

import argparse
import json
import subprocess
import yaml
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

@dataclass
class ModelConfig:
    id: str
    name: str
    tier: str
    provider: str = "unknown" 
    cost_per_mtok_input: float = 0.0
    cost_per_mtok_output: float = 0.0
    enabled: bool = True
    notes: str = ""

@dataclass
class EvaluationTask:
    model: ModelConfig
    challenge: str
    submissions_dir: Path
    num_runs: int
    attack_types: List[str]

@dataclass
class EvaluationResult:
    model_id: str
    challenge: str
    overall_asr: float
    by_attack_type: Dict[str, Dict[str, Any]]
    total_attempts: int
    total_successful: int
    output_file: Path

class MultiModelEvaluator:
    def __init__(self, config_file: Path = None):
        self.config_file = config_file or Path("models_config.yaml")
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        if not self.config_file.exists():
            print(f"Warning: Config file not found: {self.config_file}")
            return self._get_default_config()
        
        with open(self.config_file) as f:
            return yaml.safe_load(f)
    
    def _get_default_config(self) -> Dict:
        """Return default configuration if YAML not available"""
        return {
            'models': [
                # Anthropic Claude
                {'id': 'claude-sonnet-4-20250514', 'name': 'Claude Sonnet 4', 
                 'tier': 'flagship', 'provider': 'anthropic', 'enabled': True},
                
                # OpenAI GPT
                {'id': 'gpt-4o-mini', 'name': 'GPT-4o mini', 
                 'tier': 'fast', 'provider': 'openai', 'enabled': True},
                {'id': 'gpt-3.5-turbo', 'name': 'GPT-3.5 Turbo', 
                 'tier': 'legacy', 'provider': 'openai', 'enabled': True},
                
                # Google Gemini
                {'id': 'gemini-2.0-flash-exp', 'name': 'Gemini 2.0 Flash', 
                 'tier': 'flagship', 'provider': 'google', 'enabled': True},
                
                # Alibaba Qwen
                {'id': 'qwen-max', 'name': 'Qwen Max', 
                 'tier': 'flagship', 'provider': 'alibaba', 'enabled': True},
                {'id': 'qwen-plus', 'name': 'Qwen Plus', 
                 'tier': 'strong', 'provider': 'alibaba', 'enabled': True},
                {'id': 'qwen-turbo', 'name': 'Qwen Turbo', 
                 'tier': 'fast', 'provider': 'alibaba', 'enabled': True},
            ],
            'attack_types': [
                {'id': 'tool_poisoning', 'enabled': True},
                {'id': 'multimodal_attack', 'enabled': True},
                {'id': 'puppet', 'enabled': True},
            ],
            'challenges': [
                {'id': 'emailsystem', 'enabled': True},
                {'id': 'documentsystem', 'enabled': True},
                {'id': 'ETHPriceServer', 'enabled': True},
            ],
            'evaluation': {
                'default_runs': 3,
                'timeout_seconds': 120,
                'parallel_jobs': 1,
            }
        }
    
    def get_enabled_models(self, model_filter: List[str] = None) -> List[ModelConfig]:
        """Get list of enabled models"""
        models = [ModelConfig(**m) for m in self.config['models'] if m.get('enabled', True)]
        
        if model_filter:
            models = [m for m in models if m.id in model_filter]
        
        return models
    
    def get_enabled_challenges(self, challenge_filter: List[str] = None) -> List[str]:
        """Get list of enabled challenges"""
        challenges = [c['id'] for c in self.config['challenges'] if c.get('enabled', True)]
        
        if challenge_filter:
            challenges = [c for c in challenges if c in challenge_filter]
        
        return challenges
    
    def get_enabled_attack_types(self, attack_filter: List[str] = None) -> List[str]:
        """Get list of enabled attack types"""
        attacks = [a['id'] for a in self.config['attack_types'] if a.get('enabled', True)]
        
        if attack_filter:
            attacks = [a for a in attacks if a in attack_filter]
        
        return attacks
    
    def run_single_evaluation(self, task: EvaluationTask, output_dir: Path) -> EvaluationResult:
        """Run a single evaluation task"""
        
        output_file = output_dir / f"{task.model.id}__{task.challenge}.json"
        
        cmd = [
            "python", "evaluation/evaluate_source_asr.py",
            "--challenge", task.challenge,
            "--submissions-dir", str(task.submissions_dir),
            "--model", task.model.id,
            "--num-runs", str(task.num_runs),
            "--attack-types", *task.attack_types,
            "--output", str(output_file)
        ]
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Running: {task.model.name} on {task.challenge}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config['evaluation'].get('timeout_seconds', 300)
            )
            
            if result.returncode == 0 and output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)
                
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ Completed: {task.model.name} on {task.challenge} "
                      f"(ASR: {data.get('overall_asr_percentage', 'N/A')})")
                
                return EvaluationResult(
                    model_id=task.model.id,
                    challenge=task.challenge,
                    overall_asr=data.get('overall_asr', 0.0),
                    by_attack_type=data.get('by_attack_type', {}),
                    total_attempts=data.get('total_attempts', 0),
                    total_successful=data.get('total_successful', 0),
                    output_file=output_file
                )
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Failed: {task.model.name} on {task.challenge}")
                print(f"  Error: {result.stderr[:200]}")
                raise Exception(f"Evaluation failed: {result.stderr[:200]}")
                
        except subprocess.TimeoutExpired:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Timeout: {task.model.name} on {task.challenge}")
            raise
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Error: {task.model.name} on {task.challenge}: {e}")
            raise
    
    def run_batch_evaluation(
        self,
        submissions_base_dir: Path,
        output_dir: Path,
        num_runs: int = None,
        parallel_jobs: int = None,
        model_filter: List[str] = None,
        challenge_filter: List[str] = None,
        attack_filter: List[str] = None
    ) -> Dict[str, List[EvaluationResult]]:
        """Run batch evaluation across multiple models and challenges"""
        
        # Setup
        num_runs = num_runs or self.config['evaluation'].get('default_runs', 3)
        parallel_jobs = parallel_jobs or self.config['evaluation'].get('parallel_jobs', 1)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        batch_output_dir = output_dir / timestamp
        batch_output_dir.mkdir(parents=True, exist_ok=True)
        
        raw_results_dir = batch_output_dir / "raw_results"
        raw_results_dir.mkdir(exist_ok=True)
        
        # Get configurations
        models = self.get_enabled_models(model_filter)
        challenges = self.get_enabled_challenges(challenge_filter)
        attack_types = self.get_enabled_attack_types(attack_filter)
        
        print("=" * 80)
        print("MULTI-MODEL BATCH EVALUATION")
        print("=" * 80)
        print(f"Models: {len(models)}")
        for m in models:
            print(f"  - {m.name} ({m.tier})")
        print(f"Challenges: {len(challenges)}")
        for c in challenges:
            print(f"  - {c}")
        print(f"Attack Types: {', '.join(attack_types)}")
        print(f"Runs per submission: {num_runs}")
        print(f"Parallel jobs: {parallel_jobs}")
        print(f"Output directory: {batch_output_dir}")
        print("=" * 80)
        print()
        
        # Build task list
        tasks = []
        for model in models:
            for challenge in challenges:
                # Find submissions directory
                submissions_dir = submissions_base_dir / challenge
                if (submissions_base_dir / challenge / "latest").exists():
                    submissions_dir = submissions_base_dir / challenge / "latest"
                
                if not submissions_dir.exists():
                    print(f"Warning: Submissions not found for {challenge} at {submissions_dir}")
                    continue
                
                tasks.append(EvaluationTask(
                    model=model,
                    challenge=challenge,
                    submissions_dir=submissions_dir,
                    num_runs=num_runs,
                    attack_types=attack_types
                ))
        
        print(f"Total evaluations to run: {len(tasks)}")
        print()
        
        # Run evaluations
        results = []
        
        if parallel_jobs > 1:
            print(f"Running with {parallel_jobs} parallel jobs...")
            with ThreadPoolExecutor(max_workers=parallel_jobs) as executor:
                future_to_task = {
                    executor.submit(self.run_single_evaluation, task, raw_results_dir): task
                    for task in tasks
                }
                
                for future in as_completed(future_to_task):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        task = future_to_task[future]
                        print(f"Task failed: {task.model.name} on {task.challenge}: {e}")
        else:
            print("Running sequentially...")
            for i, task in enumerate(tasks, 1):
                try:
                    result = self.run_single_evaluation(task, raw_results_dir)
                    results.append(result)
                except Exception as e:
                    print(f"Task failed: {e}")
                
                print(f"Progress: {i}/{len(tasks)}")
        
        print()
        print("=" * 80)
        print(f"Completed {len(results)}/{len(tasks)} evaluations")
        print("=" * 80)
        
        # Save metadata
        metadata = {
            'timestamp': datetime.now().isoformat(),
            'num_runs': num_runs,
            'models': [asdict(m) for m in models],
            'challenges': challenges,
            'attack_types': attack_types,
            'total_tasks': len(tasks),
            'successful_tasks': len(results)
        }
        
        with open(batch_output_dir / "metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return {
            'results': results,
            'metadata': metadata,
            'output_dir': batch_output_dir
        }
    
    def generate_tables(self, batch_output_dir: Path):
        """Generate comparison tables from batch results"""
        
        from collections import defaultdict
        import csv
        
        raw_results_dir = batch_output_dir / "raw_results"
        tables_dir = batch_output_dir / "tables"
        tables_dir.mkdir(exist_ok=True)
        
        # Load metadata
        with open(batch_output_dir / "metadata.json") as f:
            metadata = json.load(f)
        
        models = {m['id']: m for m in metadata['models']}
        challenges = metadata['challenges']
        attack_types = metadata['attack_types']
        
        # Aggregate results
        # Structure: {challenge: {model_id: {attack_type: data}}}
        matrix = defaultdict(lambda: defaultdict(dict))
        
        for result_file in raw_results_dir.glob("*.json"):
            with open(result_file) as f:
                data = json.load(f)
            
            # Parse filename
            model_id, challenge = result_file.stem.split("__")
            
            # Store data
            for attack_type, attack_data in data.get('by_attack_type', {}).items():
                matrix[challenge][model_id][attack_type] = {
                    'asr': attack_data.get('asr', 0.0),
                    'asr_percentage': attack_data.get('asr_percentage', '0.0%'),
                    'total': attack_data.get('total_attempts', 0),
                    'successful': attack_data.get('successful_attacks', 0)
                }
            
            matrix[challenge][model_id]['overall'] = {
                'asr': data.get('overall_asr', 0.0),
                'asr_percentage': data.get('overall_asr_percentage', '0.0%'),
                'total': data.get('total_attempts', 0),
                'successful': data.get('total_successful', 0)
            }
        
        # Generate markdown table - Overall ASR
        with open(tables_dir / "overall_asr.md", 'w') as f:
            f.write("# Overall ASR by Model and Challenge\n\n")
            f.write("| Model | " + " | ".join(challenges) + " | Average |\n")
            f.write("|" + "---|" * (len(challenges) + 2) + "\n")
            
            for model_id, model_info in models.items():
                row = [model_info['name']]
                model_asrs = []
                
                for challenge in challenges:
                    data = matrix.get(challenge, {}).get(model_id, {}).get('overall', {})
                    asr_pct = data.get('asr_percentage', 'N/A')
                    row.append(asr_pct)
                    if data.get('asr') is not None:
                        model_asrs.append(data['asr'])
                
                if model_asrs:
                    avg = sum(model_asrs) / len(model_asrs)
                    row.append(f"{avg:.1%}")
                else:
                    row.append('N/A')
                
                f.write("| " + " | ".join(row) + " |\n")
        
        # Generate CSV - Overall ASR
        with open(tables_dir / "overall_asr.csv", 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Model', 'Tier'] + challenges + ['Average', 'Total Attempts', 'Total Successful'])
            
            for model_id, model_info in models.items():
                row = [model_info['name'], model_info['tier']]
                model_asrs = []
                total_attempts = 0
                total_successful = 0
                
                for challenge in challenges:
                    data = matrix.get(challenge, {}).get(model_id, {}).get('overall', {})
                    asr = data.get('asr')
                    if asr is not None:
                        row.append(f"{asr:.4f}")
                        model_asrs.append(asr)
                        total_attempts += data.get('total', 0)
                        total_successful += data.get('successful', 0)
                    else:
                        row.append('')
                
                if model_asrs:
                    avg = sum(model_asrs) / len(model_asrs)
                    row.append(f"{avg:.4f}")
                else:
                    row.append('')
                
                row.extend([str(total_attempts), str(total_successful)])
                writer.writerow(row)
        
        # Per-attack-type tables
        for attack_type in attack_types:
            # Markdown
            with open(tables_dir / f"{attack_type}.md", 'w') as f:
                f.write(f"# {attack_type.replace('_', ' ').title()} ASR\n\n")
                f.write("| Model | " + " | ".join(challenges) + " | Average |\n")
                f.write("|" + "---|" * (len(challenges) + 2) + "\n")
                
                for model_id, model_info in models.items():
                    row = [model_info['name']]
                    model_asrs = []
                    
                    for challenge in challenges:
                        data = matrix.get(challenge, {}).get(model_id, {}).get(attack_type, {})
                        asr_pct = data.get('asr_percentage', 'N/A')
                        row.append(asr_pct)
                        if data.get('asr') is not None:
                            model_asrs.append(data['asr'])
                    
                    if model_asrs:
                        avg = sum(model_asrs) / len(model_asrs)
                        row.append(f"{avg:.1%}")
                    else:
                        row.append('N/A')
                    
                    f.write("| " + " | ".join(row) + " |\n")
            
            # CSV
            with open(tables_dir / f"{attack_type}.csv", 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Model'] + challenges + ['Average'])
                
                for model_id, model_info in models.items():
                    row = [model_info['name']]
                    model_asrs = []
                    
                    for challenge in challenges:
                        data = matrix.get(challenge, {}).get(model_id, {}).get(attack_type, {})
                        asr = data.get('asr')
                        if asr is not None:
                            row.append(f"{asr:.4f}")
                            model_asrs.append(asr)
                        else:
                            row.append('')
                    
                    if model_asrs:
                        avg = sum(model_asrs) / len(model_asrs)
                        row.append(f"{avg:.4f}")
                    else:
                        row.append('')
                    
                    writer.writerow(row)
        
        print(f"\nTables generated in: {tables_dir}")
        print(f"  - Markdown tables: {tables_dir}/*.md")
        print(f"  - CSV tables: {tables_dir}/*.csv")

def main():
    parser = argparse.ArgumentParser(
        description="Multi-model batch evaluator for MCP Attack Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--submissions-dir",
        type=Path,
        required=True,
        help="Base directory containing challenge submissions"
    )
    
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/multi_model_batch"),
        help="Output directory for results"
    )
    
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to models config YAML file"
    )
    
    parser.add_argument(
        "--num-runs",
        type=int,
        help="Number of runs per submission (overrides config)"
    )
    
    parser.add_argument(
        "--parallel",
        type=int,
        help="Number of parallel jobs (overrides config)"
    )
    
    parser.add_argument(
        "--models",
        nargs="+",
        help="Filter to specific model IDs"
    )
    
    parser.add_argument(
        "--challenges",
        nargs="+",
        help="Filter to specific challenges"
    )
    
    parser.add_argument(
        "--attacks",
        nargs="+",
        help="Filter to specific attack types"
    )
    
    parser.add_argument(
        "--skip-tables",
        action="store_true",
        help="Skip table generation"
    )
    
    args = parser.parse_args()
    
    # Initialize evaluator
    evaluator = MultiModelEvaluator(config_file=args.config)
    
    # Run batch evaluation
    result = evaluator.run_batch_evaluation(
        submissions_base_dir=args.submissions_dir,
        output_dir=args.output_dir,
        num_runs=args.num_runs,
        parallel_jobs=args.parallel,
        model_filter=args.models,
        challenge_filter=args.challenges,
        attack_filter=args.attacks
    )
    
    # Generate tables
    if not args.skip_tables:
        evaluator.generate_tables(result['output_dir'])
    
    print("\n" + "=" * 80)
    print("EVALUATION COMPLETE")
    print("=" * 80)
    print(f"Results saved to: {result['output_dir']}")
    print(f"View tables: {result['output_dir']}/tables/")
    print(f"View raw results: {result['output_dir']}/raw_results/")

if __name__ == "__main__":
    main()