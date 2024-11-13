#!/usr/bin/env bash
set -exo pipefail

# Generate an external ECC (Elliptic Curve Cryptography) private key in PEM format
openssl ecparam -name prime256v1 -genkey -noout -out external_ecc_key.pem

# Convert the PEM-formatted ECC key to DER format, which is needed for TPM operations
openssl ec -in external_ecc_key.pem -outform DER -out external_ecc_key.der

