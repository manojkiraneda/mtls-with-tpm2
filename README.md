# mtls-with-tpm2

## Compilation:
```bash
## Enter the yocto development sdk

## compile client
$CXX -o client client_demo.cpp -L/home/manojeda/sdk/sysroots/armv7ahf-vfpv4d16-openbmc-linux-gnueabi/usr/lib -L/home/manojeda/sdk/sysroots/armv7ahf-vfpv4d16-openbmc-linux-gnueabi/lib/ossl-modules/ -lssl -lcrypto -ltss2-tcti-device -ltss2-sys -std=c++20

## compile server

$CXX -o server server_demo.cpp -L/home/manojeda/sdk/sysroots/armv7ahf-vfpv4d16-openbmc-linux-gnueabi/usr/lib -L/home/manojeda/sdk/sysroots/armv7ahf-vfpv4d16-openbmc-linux-gnueabi/lib/ossl-modules/ -lssl -lcrypto -ltss2-tcti-device -ltss2-sys -std=c++20

```
