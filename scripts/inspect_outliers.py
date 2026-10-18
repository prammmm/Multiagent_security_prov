import json
import os
import re

DATA_DIR = r"D:\multiagent_security_prov\Multiagent_security_prov\data"

def inspect_outliers():
    b_path = os.path.join(DATA_DIR, "question.jsonl")
    base = {json.loads(l)["question_id"]: json.loads(l) for l in open(b_path, encoding="utf-8")}
    
    outliers = [
        ("misspellings", 214),
        ("slang", 32),
        ("slang", 58),
        ("slang", 161),
        ("uncommon_dialects", 261)
    ]
    
    for var, qid in outliers:
        v_path = os.path.join(DATA_DIR, f"question_{var}.jsonl")
        v_data = {json.loads(l)["question_id"]: json.loads(l) for l in open(v_path, encoding="utf-8")}
        
        b_rec = base[qid]
        v_rec = v_data[qid]
        
        bt = b_rec["turns"][0]
        vt = v_rec["turns"][0]
        
        b_tok = re.findall(r"\b\w+\b", bt.lower())
        v_tok = re.findall(r"\b\w+\b", vt.lower())
        
        print(f"=== {var} | QID {qid} | Cat: {b_rec['category']} ===")
        print(f"Base: {len(bt)} chars, {len(b_tok)} words")
        print(f"Var:  {len(vt)} chars, {len(v_tok)} words")
        # Mask out sensitive content: show token length diff and masked alignment
        b_masked = " ".join([f"{w[0]}***" if len(w)>2 else w for w in b_tok])
        v_masked = " ".join([f"{w[0]}***" if len(w)>2 else w for w in v_tok])
        print(f"Masked Base: {b_masked}")
        print(f"Masked Var:  {v_masked}\n")

if __name__ == "__main__":
    inspect_outliers()
