#!/bin/bash

/usr/bin/mitmproxy \
-w log.txt \
--mode reverse:https://bad-welp.com \
--listen-host 0.0.0.0 \
--listen-port 443 \
--set console_eventlog_verbosity=info \
--set block_global=false \
-s ./protech.py \
--certs *=./cert.pem \
--ssl-insecure
