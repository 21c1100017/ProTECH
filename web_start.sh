#!/bin/bash

/usr/bin/mitmweb \
-w log.txt \
--mode reverse:https://bad-welp.com \
--listen-host 0.0.0.0 \
--listen-port 443 \
--set termlog_verbosity=info \
--set block_global=false \
-s protech.py \
--certs *=../cert.pem \
--ssl-insecure \
--web-host 0.0.0.0 \
--web-port 8080
