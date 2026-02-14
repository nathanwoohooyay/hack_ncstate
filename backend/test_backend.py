import requests
import json

URL = "http://127.0.0.1:8000/analyze/upload"

payload = {
    "text": """
AWS_SECRET_ACCESS_KEY=abcd1234abcd1234abcd
password=mysecretpassword
SSN: 123-45-6789
""",
    "filename": "test.env",
    "mime_type": "text/plain",
    "page_url": "http://localhost"
}

print("Sending request...")

response = requests.post(URL, json=payload)

print("\nStatus Code:", response.status_code)
print("\nResponse JSON:")
print(json.dumps(response.json(), indent=2))