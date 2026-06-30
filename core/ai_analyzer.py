import requests
import json

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "llama3.1:8b"

def ask_hodor(prompt):
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=300)
        data = response.json()
        return data.get("response", "Cevap alinamadi.")
    except Exception as e:
        return f"Ollama baglanti hatasi: {e}"

def analyze_with_ai(connections_log):
    print("\n[HODOR AI] Tehdit analizi baslatiliyor...\n")
    print("Model yukleniyor, lutfen bekleyin (1-2 dakika)...\n")
    
    prompt = f"""You are HODOR, a cybersecurity AI agent. Analyze these network connections and identify any suspicious activity. Be concise and clear.

Network connections:
{connections_log[:2000]}

Respond in this format:
THREAT LEVEL: (LOW/MEDIUM/HIGH)
SUSPICIOUS: (list any suspicious connections or NONE)
RECOMMENDATION: (what to do)"""

    response = ask_hodor(prompt)
    print("=== HODOR AI ANALIZ ===")
    print(response)
    return response

if __name__ == "__main__":
    with open("logs/connections.log", "r", encoding="utf-8") as f:
        log_data = f.read()
    analyze_with_ai(log_data)
