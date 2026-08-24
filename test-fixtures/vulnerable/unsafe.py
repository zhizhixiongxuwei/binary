import hashlib
import os
import pickle
import requests
import subprocess


def analyze(user_input, raw, url):
    eval(user_input)
    os.system(user_input)
    subprocess.call(user_input, shell=True)
    pickle.loads(raw)
    hashlib.md5(raw).hexdigest()
    requests.get(url, verify=False)
