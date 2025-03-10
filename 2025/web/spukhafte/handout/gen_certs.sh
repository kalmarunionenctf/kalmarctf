#!/bin/sh
rm -rf certs/
mkdir certs/
openssl req -x509 -newkey rsa:4096 -keyout certs/cert.key -out certs/cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=*.kalmarctf.local"