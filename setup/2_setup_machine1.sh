#!/usr/bin/env bash
set -exo pipefail

####### Copy the external_ecc_key.pem file into machine 1, then do the following steps ###########


########## Generating the CA certificate on Machine 1 ###############################

# Create a primary key in the TPM using the elliptic curve cryptography (ECC) algorithm
tpm2_createprimary -C o -G ecc -c primary_ctx

# Import the external ECC key into the TPM using the primary key context created above
tpm2_import -C primary_ctx -G ecc -i external_ecc_key.pem -u imported_ecc_key.pub -r imported_ecc_key.priv

# Load the imported ECC key into the TPM
tpm2_load -C primary_ctx -u imported_ecc_key.pub -r imported_ecc_key.priv -c imported_ecc_key.ctx

# Make the loaded key persistent in the TPM at a specific handle (0x81010001 in this case)
tpm2_evictcontrol -C o -c imported_ecc_key.ctx 0x81010001

# Generate a CA certificate using the loaded key at handle 0x81010001
openssl req -provider tpm2 -provider default -x509 -sha256 -nodes -days 365 -subj "/CN=IBM CA/O=IBM/C=US" -key handle:0x81010001 -outform der -out local-ca.der

# print the generated CA certificate
openssl x509 -in local-ca.der -inform der -text -noout

############ Generating the TLS auth certificate on Machine 1 ##########################

# create primary key under owner hierarchy
tpm2_createprimary -G ecc -c primary.ctx
# make primary key persisted at handle 0x81000000
tpm2_evictcontrol -c primary.ctx 0x81000000
# remove all transient objects
tpm2_flushcontext -t
# create and output an rsa keypair (rsakey.pub, rsakey.priv) which is protected by the primary key
tpm2_create -G rsa3072 -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign|noda" -C 0x81000000 -u platform.pub -r platform.priv
# remove all transient objects
tpm2_flushcontext -t
# load the rsa keypair into tpm
tpm2_load -C primary.ctx -u platform.pub -r platform.priv -c platform.ctx
# make rsa keypair persisted at handle 0x81000001
tpm2_evictcontrol -c platform.ctx 0x81000001
# remove all transient objects
tpm2_flushcontext -t

cat > alias_cert.conf <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_alias
prompt = no

[ req_distinguished_name ]
C  = US
ST = Austin
L  = Texas
O  = IBM
CN = Device 1 Alias Certificate

[ v3_alias ]
basicConstraints        = CA:false
nsCertType              = server
nsComment               = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid,issuer:always
keyUsage                = critical,digitalSignature,keyEncipherment
extendedKeyUsage        = serverAuth,clientAuth
EOF

# Generate Certificate signing request for tls auth certificate
openssl req -provider tpm2 -provider default -new -key handle:0x81000001 -out alias.csr -config alias.conf

# Request CA to sign the certificate signing request
openssl x509 -provider tpm2 -provider default -req -in alias.csr -CA local-ca.der -CAkey handle:0x81010001 -CAcreateserial -outform der -out alias_cert.der -days 30 -extensions v3_alias -extfile alias.conf

