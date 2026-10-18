import json
import time
import urllib.request
import subprocess

url = "http://127.0.0.1:11434/api/generate"
payload = {
    "model": "mistral-nemo:12b-instruct-2407-q4_K_M",
    "prompt": "Hello! Say 'Ready' in JSON: {\"status\": \"Ready\"}",
    "stream": False,
    "options": {
        "num_ctx": 2048,
        "temperature": 0.0,
        "num_predict": 64,
    }
}

print("Sending request to load Mistral Nemo 12B...")
t0 = time.time()
req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=120) as resp:
    data = json.loads(resp.read().decode("utf-8"))
dt = time.time() - t0
print(f"Inference completed in {dt:.2f}s")
print("Response:", data.get("response", "").strip())

print("\n--- Ollama PS ---")
subprocess.run(["ollama", "ps"])

print("\n--- GPU Memory (nvidia-smi) ---")
subprocess.run(["nvidia-smi", "--query-gpu=memory.used,memory.free,memory.total", "--format=csv"])
