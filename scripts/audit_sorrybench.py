import json
import os
import sys
from collections import Counter, defaultdict

DATA_DIR = r"D:\multiagent_security_prov\Multiagent_security_prov\data"
FILES = {
    "base": "question.jsonl",
    "misspellings": "question_misspellings.jsonl",
    "slang": "question_slang.jsonl",
    "uncommon_dialects": "question_uncommon_dialects.jsonl"
}

def audit_files():
    data = {}
    stats = {}
    
    for key, fname in FILES.items():
        fpath = os.path.join(DATA_DIR, fname)
        if not os.path.exists(fpath):
            print(f"ERROR: {fpath} not found!")
            continue
            
        file_size = os.path.getsize(fpath)
        records = []
        parse_errors = 0
        null_counts = defaultdict(int)
        duplicate_ids = []
        seen_ids = set()
        
        with open(fpath, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    obj = json.loads(line_str)
                    records.append(obj)
                    qid = obj.get("question_id")
                    if qid in seen_ids:
                        duplicate_ids.append(qid)
                    seen_ids.add(qid)
                    
                    for field in ["question_id", "category", "turns", "prompt_style"]:
                        if field not in obj or obj[field] is None:
                            null_counts[field] += 1
                except Exception as e:
                    parse_errors += 1
                    print(f"Parse error in {fname} line {line_idx}: {e}")
                    
        data[key] = {r["question_id"]: r for r in records if "question_id" in r}
        stats[key] = {
            "filename": fname,
            "filepath": fpath,
            "file_size": file_size,
            "record_count": len(records),
            "parse_errors": parse_errors,
            "duplicate_ids": duplicate_ids,
            "unique_ids_count": len(seen_ids),
            "null_counts": dict(null_counts),
            "prompt_styles": Counter(r.get("prompt_style") for r in records),
            "categories": Counter(r.get("category") for r in records),
            "turns_lengths": Counter(len(r.get("turns", [])) for r in records)
        }
        
    print("=== SUMMARY STATS PER FILE ===")
    for key, s in stats.items():
        print(f"\n--- {key} ({s['filename']}) ---")
        print(f"Size: {s['file_size']} bytes")
        print(f"Record Count: {s['record_count']}")
        print(f"Unique IDs: {s['unique_ids_count']}, Duplicates: {len(s['duplicate_ids'])}")
        print(f"Parse Errors: {s['parse_errors']}")
        print(f"Null/Missing Counts: {s['null_counts']}")
        print(f"Prompt Styles: {dict(s['prompt_styles'])}")
        print(f"Category counts (top 5): {s['categories'].most_common(5)}")
        print(f"Turns lengths: {dict(s['turns_lengths'])}")

    # Cross-variant alignment
    base_ids = set(data["base"].keys())
    print("\n=== CROSS-VARIANT ALIGNMENT ===")
    print(f"Base unique IDs count: {len(base_ids)}")
    
    for key in ["misspellings", "slang", "uncommon_dialects"]:
        var_ids = set(data[key].keys())
        shared = base_ids & var_ids
        missing_in_var = base_ids - var_ids
        extra_in_var = var_ids - base_ids
        pct_shared = (len(shared) / len(base_ids)) * 100 if base_ids else 0
        print(f"\nVariant: {key}")
        print(f"  Shared with base: {len(shared)} / {len(base_ids)} ({pct_shared:.2f}%)")
        print(f"  Missing in variant: {len(missing_in_var)} (IDs: {sorted(list(missing_in_var))[:10]})")
        print(f"  Extra in variant: {len(extra_in_var)} (IDs: {sorted(list(extra_in_var))[:10]})")
        
        # Check category agreement
        cat_mismatch = []
        for qid in shared:
            base_cat = data["base"][qid].get("category")
            var_cat = data[key][qid].get("category")
            if base_cat != var_cat:
                cat_mismatch.append((qid, base_cat, var_cat))
        print(f"  Category mismatches with base: {len(cat_mismatch)}")

        # Check prompt differences
        identical_to_base = 0
        diff_lengths = []
        for qid in shared:
            base_prompt = data["base"][qid]["turns"][0] if data["base"][qid].get("turns") else ""
            var_prompt = data[key][qid]["turns"][0] if data[key][qid].get("turns") else ""
            if base_prompt == var_prompt:
                identical_to_base += 1
            else:
                diff_lengths.append(abs(len(var_prompt) - len(base_prompt)))
        print(f"  Identical to base prompt: {identical_to_base} / {len(shared)}")
        if diff_lengths:
            print(f"  Avg absolute char length diff: {sum(diff_lengths)/len(diff_lengths):.2f}")

    # Check for presence of tool / agent / execution fields
    print("\n=== FIELD PRESENCE CHECK FOR AGENT/ACTION CAPABILITIES ===")
    all_keys = set()
    for key, records_dict in data.items():
        for r in records_dict.values():
            all_keys.update(r.keys())
    print("All unique keys observed across all datasets:", sorted(list(all_keys)))
    
    agent_fields = ["tool", "tools", "action", "execution", "history", "trace", "observations", "agent", "intent", "ground_truth", "output"]
    found_agent_fields = [f for f in agent_fields if f in all_keys]
    print(f"Agent/Tool/Trace fields found: {found_agent_fields}")

if __name__ == "__main__":
    audit_files()
