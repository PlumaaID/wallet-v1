#!/usr/bin/env bash

set -euo pipefail

openssl rsa -pubin -outform DER -in keys/$1/private.pem -noout -modulus | sed 's/Modulus=//g'
