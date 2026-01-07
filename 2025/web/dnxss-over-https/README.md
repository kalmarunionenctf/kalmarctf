# DNXSS-over-HTTPS

Do you like DNS-over-HTTPS? Well, I'm proxying `https://dns.google/`! Would be cool if you can find an XSS!
```sh
curl http://localhost:8008/report -H "Content-Type: application/json" -d '{"url":"http://proxy/"}'
```
