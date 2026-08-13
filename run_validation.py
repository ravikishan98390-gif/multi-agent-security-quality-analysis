import asyncio
import os
from collections import defaultdict
from agents.code_analysis_agent import analyze as quality_analyze
from agents.security_agent import analyze as security_analyze

# The expected findings for each validation file.
# Format: filename -> list of tuples: (category, source_agent)
ANSWER_KEY = {
    "01_clean_service.py": [],
    "02_owasp_sqli.java": [
        ("hardcoded_secret", "security"),
        ("sql_injection", "security"),
        ("long_method", "code_analysis")
    ],
    "03_messy_flask.py": [
        ("broken_access_control", "security"),
        ("xss", "security"),
        ("high_complexity", "code_analysis"),
        ("deep_nesting", "code_analysis")
    ],
    "04_legacy_crypto.java": [
        ("broken_auth", "security"),  # Specifically MD5
        ("high_instantiation_fanout", "code_analysis"),
        ("duplicate_code", "code_analysis")
    ]
}

def analyze_results(expected: dict[str, list[tuple[str, str]]], actual_findings: dict[str, list]) -> None:
    tp, fp, fn = 0, 0, 0
    total_expected = sum(len(issues) for issues in expected.values())

    for filename, expected_issues in expected.items():
        print(f"\n======================================")
        print(f"File: {filename}")
        print(f"======================================")
        
        actual_issues_for_file = actual_findings.get(filename, [])
        # Filter out extremely noisy non-critical issues from validation stats
        actual_categories = [
            (f.category, f.source_agent) for f in actual_issues_for_file 
            if f.category not in ("poor_naming", "tooling_warning")
        ]
        
        # Determine True Positives & False Negatives
        matched = []
        for issue in expected_issues:
            if issue in actual_categories:
                print(f"[DETECTED] {issue[0]} (Agent: {issue[1]})")
                tp += 1
                matched.append(issue)
            else:
                print(f"[MISSED]   {issue[0]} (Agent: {issue[1]})")
                fn += 1
                
        # Determine False Positives
        for actual in actual_categories:
            if actual not in expected_issues and actual not in matched:
                print(f"[FALSE ALARM] {actual[0]} (Agent: {actual[1]})")
                fp += 1

    print("\n======================================")
    print("VALIDATION SUMMARY")
    print("======================================")
    print(f"Planted Issues (Ground Truth): {total_expected}")
    print(f"Caught Issues (True Positives): {tp}")
    print(f"Missed Issues (False Negatives): {fn}")
    print(f"False Alarms (False Positives): {fp}")
    
    if tp > 0:
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        print(f"Precision: {precision:.2f}")
        print(f"Recall:    {recall:.2f}")
    else:
        print("Precision: 0.00")
        print("Recall:    0.00")

async def main():
    validation_dir = "validation"
    if not os.path.exists(validation_dir):
        print(f"Directory {validation_dir} not found.")
        return

    actual_results = {}
    
    # Process each file sequentially for clarity
    for filename in ANSWER_KEY.keys():
        filepath = os.path.join(validation_dir, filename)
        if not os.path.exists(filepath):
            print(f"File {filepath} not found.")
            continue
            
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()
            
        language = "python" if filename.endswith(".py") else "java"
        
        print(f"Analyzing {filename}...")
        try:
            q_task = asyncio.to_thread(quality_analyze, code, language)
            s_task = asyncio.to_thread(security_analyze, code, language)
            q_findings, s_findings = await asyncio.gather(q_task, s_task)
            actual_results[filename] = q_findings + s_findings
        except Exception as e:
            print(f"Error analyzing {filename}: {e}")
            actual_results[filename] = []
            
    analyze_results(ANSWER_KEY, actual_results)

if __name__ == "__main__":
    asyncio.run(main())
