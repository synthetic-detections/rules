# Legitimate Hugging Face API client for text generation
# Should NOT match any PROMPTSTEAL rules

import requests

API_URL = "https://router.huggingface.co/hyperbolic/v1/chat/completions"
MODEL = "Qwen/Qwen2.5-Coder-32B-Instruct"

def generate_text(prompt):
    payload = {
        "messages": [{"role": "user", "content": prompt}],
        "model": MODEL,
        "temperature": 0.7
    }
    response = requests.post(API_URL, json=payload)
    return response.json()

if __name__ == "__main__":
    result = generate_text("Explain quantum computing in simple terms")
    print(result)
