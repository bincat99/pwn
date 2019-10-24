import requests

s = requests.Session()
url = "http://200.200.200.100:8888/auth.php"
cookies = {"PHPSESSID": "rj2090mhel7e0g124i4cfnph80"}
  
with open("answer", "r") as f:
  for l in f:
    a = l.split (" ")
    prob = int (a[0])
    key = a[2][:-1]
    data = {"key": key, "prob": prob}
    r = s.post(url, data = data, cookies = cookies)
    print r.content
