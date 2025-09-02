#!/bin/bash

# make sure to clean up the tpm handles 

# Device 1 cleanup
tpm2_evictcontrol -C p -c 0x81010001
tpm2_nvundefine -C p 0x1500021
tpm2_evictcontrol -C p -c 0x81010002
tpm2_nvundefine -C p 0x1500022

# Device 2 cleanup
tpm2_evictcontrol -C p -c 0x81010003
tpm2_nvundefine -C p 0x1500023
tpm2_evictcontrol -C p -c 0x81010004
tpm2_nvundefine -C p 0x1500024


# Create separate directories for Device 1 and Device 2
mkdir -p device1 device2

# TPM Handles and NV indices for Device 1
CA1_HANDLE=0x81010001
CA1_NV_INDEX=0x1500021
ALIAS1_HANDLE=0x81010002
ALIAS1_CERT_NV_INDEX=0x1500022

# TPM Handles and NV indices for Device 2
CA2_HANDLE=0x81010003
CA2_NV_INDEX=0x1500023
ALIAS2_HANDLE=0x81010004
ALIAS2_CERT_NV_INDEX=0x1500024

# Generate configuration files for cert generation in each device's folder
echo "Creating configuration files in device1 and device2 directories..."
mkdir -p device1

cat > device1/ca_cert.conf <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
C  = US
ST = Texas
L  = Austin
O  = IBM
CN = Device 1 Local CA

[ v3_ca ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer
basicConstraints        = critical,CA:true
keyUsage                = critical,cRLSign,keyCertSign
EOF

cat > device1/device_cert.conf <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_intermediate_ca
prompt = no

[ req_distinguished_name ]
C  = US
ST = Austin
L  = Texas
O  = IBM
CN = Device 1 Certificate

[ v3_intermediate_ca ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid,issuer
basicConstraints        = critical,CA:true,pathlen:0
keyUsage                = critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign
extendedKeyUsage        = serverAuth,clientAuth
EOF

cat > device1/alias_cert.conf <<EOF
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

cat > device2/ca_cert.conf <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
C  = US
ST = Texas
L  = Austin
O  = IBM
CN = Device 2 Local CA

[ v3_ca ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always, issuer
basicConstraints        = critical, CA:true
keyUsage                = critical, digitalSignature, cRLSign, keyCertSign
EOF

cat > device2/device_cert.conf <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_intermediate_ca
prompt = no

[ req_distinguished_name ]
C  = US
ST = Austin
L  = Texas
O  = IBM
CN = Device 2 Certificate

[ v3_intermediate_ca ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid,issuer
basicConstraints        = critical,CA:true,pathlen:0
keyUsage                = critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign
extendedKeyUsage        = serverAuth,clientAuth
EOF

cat > device2/alias_cert.conf <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_alias
prompt = no

[ req_distinguished_name ]
C  = US
ST = Austin
L  = Texas
O  = IBM
CN = Device 2 Alias Certificate

[ v3_alias ]
basicConstraints        = CA:FALSE
nsComment               = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid, issuer
keyUsage                = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
EOF

echo "===== Device 1: Generate CA Key Pair and Store CA Private Key in TPM Handle ====="
cd device1
tpm2_createprimary -C o -G rsa -c ca_primary.ctx
tpm2_create -C ca_primary.ctx -G rsa -u ca_public.pem -r ca_private.pem
tpm2_load -C ca_primary.ctx -u ca_public.pem -r ca_private.pem -c ca_key.ctx
tpm2_evictcontrol -C o -c ca_key.ctx $CA1_HANDLE

echo "Generating Device 1 CA Certificate..."
openssl req -provider tpm2 -provider default -new -x509 -key "handle:$CA1_HANDLE" -out ca_cert.der -days 365 -config ca_cert.conf -extensions v3_ca -outform der

echo "Storing Device 1 CA Certificate in TPM NV RAM at index $CA1_NV_INDEX..."
tpm2_nvdefine $CA1_NV_INDEX -C o -s 2048 -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite $CA1_NV_INDEX -C o -i ca_cert.der


echo "===== Device 1: Generate Alias Key Pair and Alias Certificate ====="
tpm2_createprimary -C o -G rsa -c alias_primary.ctx
tpm2_create -C alias_primary.ctx -G rsa -u alias_public.pem -r alias_private.pem
tpm2_load -C alias_primary.ctx -u alias_public.pem -r alias_private.pem -c alias_key.ctx
tpm2_evictcontrol -C o -c alias_key.ctx $ALIAS1_HANDLE

echo "Generating Device 1 Alias Certificate Signing Request (CSR)..."
openssl req -provider tpm2 -provider default -new -key "handle:$ALIAS1_HANDLE" -out alias.csr -config alias_cert.conf

echo "Signing Device 1 Alias Certificate with CA..."
tpm2_nvread $CA1_NV_INDEX -C o | openssl x509 -inform der -outform pem | openssl x509 -provider tpm2 -provider default -req -in alias.csr -CA /dev/stdin -CAkey "handle:$CA1_HANDLE" -CAserial ./ca.srl -CAcreateserial -outform der -out alias_cert.der -days 30  -extensions v3_alias -extfile alias_cert.conf

echo "Storing Device 1 Alias Certificate in TPM NV RAM at index $ALIAS1_CERT_NV_INDEX..."
tpm2_nvdefine $ALIAS1_CERT_NV_INDEX -C o -s 2048 -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite $ALIAS1_CERT_NV_INDEX -C o -i alias_cert.der


cd ..
echo "===== Device 2: Generate CA Key Pair and Store CA Private Key in TPM Handle ====="
cd device2
tpm2_createprimary -C o -G rsa -c ca_primary.ctx
tpm2_create -C ca_primary.ctx -G rsa -u ca_public.pem -r ca_private.pem
tpm2_load -C ca_primary.ctx -u ca_public.pem -r ca_private.pem -c ca_key.ctx
tpm2_evictcontrol -C o -c ca_key.ctx $CA2_HANDLE

echo "Generating Device 2 CA Certificate..."
openssl req -provider tpm2 -provider default -new -x509 -key "handle:$CA2_HANDLE" -out ca_cert.der -days 365 -config ca_cert.conf -extensions v3_ca -outform der

echo "Storing Device 2 CA Certificate in TPM NV RAM at index $CA2_NV_INDEX..."
tpm2_nvdefine $CA2_NV_INDEX -C o -s 2048 -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite $CA2_NV_INDEX -C o -i ca_cert.der

echo "===== Device 2: Generate Alias Key Pair and Alias Certificate ====="
tpm2_createprimary -C o -G rsa -c alias_primary.ctx
tpm2_create -C alias_primary.ctx -G rsa -u alias_public.pem -r alias_private.pem
tpm2_load -C alias_primary.ctx -u alias_public.pem -r alias_private.pem -c alias_key.ctx
tpm2_evictcontrol -C o -c alias_key.ctx $ALIAS2_HANDLE

echo "Generating Device 2 Alias Certificate Signing Request (CSR)..."
openssl req -provider tpm2 -provider default -new -key "handle:$ALIAS2_HANDLE" -out alias.csr -config alias_cert.conf

echo "Signing Device 2 Alias Certificate with CA..."
tpm2_nvread $CA2_NV_INDEX -C o | openssl x509 -inform der -outform pem | openssl x509 -provider tpm2 -provider default -req -in alias.csr -CA /dev/stdin -CAkey "handle:$CA2_HANDLE" -CAserial ./ca.srl -CAcreateserial -outform der -out alias_cert.der -days 30 -extensions v3_alias -extfile alias_cert.conf

echo "Storing Device 2 Alias Certificate in TPM NV RAM at index $ALIAS2_CERT_NV_INDEX..."
tpm2_nvdefine $ALIAS2_CERT_NV_INDEX -C o -s 2048 -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite $ALIAS2_CERT_NV_INDEX -C o -i alias_cert.der

cd ..

echo "===== Cleanup Temporary Files ====="
#rm -f *.ctx *.pem *.csr *.der *.srl device1/*.conf device2/*.conf $TPM_PROVIDER_CONF
echo "All steps completed successfully for Device 1 and Device 2!"

# TPM Handles and NV indices for Device 1
echo "Device 1 CA key : $CA1_HANDLE"
echo "Device 1 CA cert: $CA1_NV_INDEX"
echo "Device 1 TLS key: $ALIAS1_HANDLE"
echo "Device 1 TLS cert : $ALIAS1_CERT_NV_INDEX"

# TPM Handles and NV indices for Device 2
echo "Device 2 CA key : $CA2_HANDLE"
echo "Device 2 CA cert : $CA2_NV_INDEX"
echo "Device 2 TLS Key : $ALIAS2_HANDLE"
echo "Device 2 TLS cert : $ALIAS2_CERT_NV_INDEX"

