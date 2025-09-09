import os

def explain_event(details: dict) -> str:
    if not os.environ.get("OPENAI_API_KEY") or not details:
        return ""
    try:
        import requests, json
        api = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            "Content-Type": "application/json"
        }
        prompt = "You are a cybersecurity assistant. Briefly explain why the following event could be suspicious and suggest one remediation step. Event JSON: " + json.dumps(details)
        payload = {
            "model": os.environ.get("GENAI_MODEL","gpt-4o-mini"),
            "messages": [{"role":"user","content": prompt}],
            "temperature": 0.2
        }
        r = requests.post(api, headers=headers, json=payload, timeout=10)
        if r.ok:
            return r.json()["choices"][0]["message"]["content"]
    except Exception:
        pass
    return ""
