import json
import os
import re
from collections import Counter, defaultdict
import numpy as np

DATA_DIR = r"D:\multiagent_security_prov\Multiagent_security_prov\data"
FILES = {
    "base": "question.jsonl",
    "misspellings": "question_misspellings.jsonl",
    "slang": "question_slang.jsonl",
    "uncommon_dialects": "question_uncommon_dialects.jsonl"
}

def load_dataset(fname):
    fpath = os.path.join(DATA_DIR, fname)
    records = {}
    with open(fpath, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                obj = json.loads(line_str)
                records[obj["question_id"]] = obj
    return records

def tokenize(text):
    return re.findall(r"\b\w+\b", text.lower())

def jaccard_similarity(tokens1, tokens2):
    s1, s2 = set(tokens1), set(tokens2)
    if not s1 and not s2:
        return 1.0
    return len(s1 & s2) / len(s1 | s2)

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def analyze_all():
    datasets = {k: load_dataset(v) for k, v in FILES.items()}
    base_data = datasets["base"]
    qids = sorted(list(base_data.keys()))
    
    print(f"Total Base QIDs: {len(qids)} (Min: {min(qids)}, Max: {max(qids)})")
    
    # 1. Length & Word Count Distributions
    print("\n--- Length & Token Statistics ---")
    for key, data in datasets.items():
        char_lens = [len(data[qid]["turns"][0]) for qid in qids]
        word_counts = [len(tokenize(data[qid]["turns"][0])) for qid in qids]
        print(f"Variant: {key}")
        print(f"  Char Length: mean={np.mean(char_lens):.1f}, std={np.std(char_lens):.1f}, min={np.min(char_lens)}, max={np.max(char_lens)}, median={np.median(char_lens):.1f}")
        print(f"  Word Count:  mean={np.mean(word_counts):.1f}, std={np.std(word_counts):.1f}, min={np.min(word_counts)}, max={np.max(word_counts)}, median={np.median(word_counts):.1f}")

    # 2. Pairwise Divergence from Base
    print("\n--- Pairwise Divergence from Base (N=440 pairs) ---")
    for key in ["misspellings", "slang", "uncommon_dialects"]:
        var_data = datasets[key]
        jaccards = []
        norm_edits = []
        char_diffs = []
        word_diffs = []
        low_sim_cases = []
        
        for qid in qids:
            b_text = base_data[qid]["turns"][0]
            v_text = var_data[qid]["turns"][0]
            b_tokens = tokenize(b_text)
            v_tokens = tokenize(v_text)
            
            j = jaccard_similarity(b_tokens, v_tokens)
            jaccards.append(j)
            
            # Normalized edit distance: edit_dist / max(len(b), len(v))
            ed = levenshtein_distance(b_text, v_text)
            norm_ed = ed / max(len(b_text), len(v_text)) if max(len(b_text), len(v_text)) > 0 else 0
            norm_edits.append(norm_ed)
            
            char_diffs.append(len(v_text) - len(b_text))
            word_diffs.append(len(v_tokens) - len(b_tokens))
            
            if j < 0.20:
                low_sim_cases.append((qid, j, norm_ed, len(b_tokens), len(v_tokens)))
                
        print(f"\nVariant: {key} vs. Base")
        print(f"  Token Jaccard Sim:  mean={np.mean(jaccards):.3f}, std={np.std(jaccards):.3f}, min={np.min(jaccards):.3f}, max={np.max(jaccards):.3f}, median={np.median(jaccards):.3f}")
        print(f"  Normalized Edit Dist: mean={np.mean(norm_edits):.3f}, std={np.std(norm_edits):.3f}, min={np.min(norm_edits):.3f}, max={np.max(norm_edits):.3f}, median={np.median(norm_edits):.3f}")
        print(f"  Char Length Delta (Var - Base): mean={np.mean(char_diffs):.1f}, std={np.std(char_diffs):.1f}, min={np.min(char_diffs)}, max={np.max(char_diffs)}")
        print(f"  Word Count Delta  (Var - Base): mean={np.mean(word_diffs):.1f}, std={np.std(word_diffs):.1f}, min={np.min(word_diffs)}, max={np.max(word_diffs)}")
        print(f"  Low Token Similarity (Jaccard < 0.20): {len(low_sim_cases)} cases")
        if low_sim_cases:
            print(f"    Sample Low Sim QIDs (first 5): {[c[0] for c in low_sim_cases[:5]]}")

    # 3. Linguistic Nature Assessment (Non-sensitive vocabulary / style inspection)
    print("\n--- Linguistic Feature Observations ---")
    # Misspellings: character swap/typo rate
    # Slang: common slang words introduced
    # Dialect: dialectal particles
    for key in ["misspellings", "slang", "uncommon_dialects"]:
        var_data = datasets[key]
        added_words = Counter()
        for qid in qids:
            b_words = set(tokenize(base_data[qid]["turns"][0]))
            v_words = set(tokenize(var_data[qid]["turns"][0]))
            diff_words = v_words - b_words
            added_words.update(diff_words)
        print(f"\nVariant: {key} - Top 15 most frequent unique tokens introduced:")
        print(added_words.most_common(15))

if __name__ == "__main__":
    analyze_all()
