#!/usr/bin/env bash

set -euo pipefail

## Public keys
openssl x509 -inform der -in keys/other/CACX7605101P8_20230509114423/cacx7605101p8.cer -pubkey -noout -outform der > keys/other/public.pem
openssl x509 -inform der -in keys/owner/FUNK671228PH6_20230509114807/funk671228ph6.cer -pubkey -noout -outform der > keys/owner/public.pem

## Private keys
openssl rsa --passin file:keys/other/CACX7605101P8_20230509114423/passphrase.txt -inform der -outform pem -in keys/other/CACX7605101P8_20230509114423/Claveprivada_FIEL_CACX7605101P8_20230509_114423.key -out keys/other/private.pem
openssl rsa --passin file:keys/owner/FUNK671228PH6_20230509114807/passphrase.txt -inform der -outform pem -in keys/owner/FUNK671228PH6_20230509114807/Claveprivada_FIEL_FUNK671228PH6_20230509_114807.key -out keys/owner/private.pem
