import requests
import itertools
import time

# This code is for silver award

url = "https://hhc24-frostykeypad.holidayhackchallenge.com"
res = "/submit?id=null"

#d = { "answer": "51687" }
h = { "Content-Type" : "application/json" }

#response = requests.post(url + res, json=d, headers=h)

#print(response.text)
#print(response.json())

# 2678 = SANT
# SANTA is the code

# Correct answer: 72682

guesslist = [ "" ] * 5
for perm in itertools.permutations(["2","6","7","8"]):
    guesslist[0] = perm[0] # S
    guesslist[1] = perm[1] # A
    guesslist[2] = perm[2] # N
    guesslist[3] = perm[3] # T
    guesslist[4] = perm[1] # A
    guess = "".join(guesslist)
    print(guess)
    d = { "answer": guess }
    response = requests.post(url + res, json=d, headers=h)
    resp = response.json()
    if "error" in resp.keys():
        print("wrong key!")
    else:
        print("seems right!")
        print(response.text)
        break
    time.sleep(1)


