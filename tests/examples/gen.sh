#!/bin/bash -xe

cfssl gencert -initca ca-csr.json > ca.json
cfssljson -bare ca < ca.json

cfssl gencert -config config.json -ca-key ca-key.pem -ca ca.pem -profile subca subca-csr.json > subca.json
cfssljson -bare subca < subca.json

cfssl gencert -config config.json -ca-key subca-key.pem -ca subca.pem cert-csr.json > cert.json
cfssljson -bare cert < cert.json
cat cert.pem subca.pem > cert.chained.pem

cfssl gencert -config config.json -ca-key subca-key.pem -ca subca.pem cert-ec-csr.json > cert-ec.json
cfssljson -bare cert-ec < cert-ec.json
cat cert-ec.pem subca.pem > cert-ec.chained.pem

cfssl gencert -config config.json -ca-key subca-key.pem -ca subca.pem cert-p384-csr.json > cert-p384.json
cfssljson -bare cert-p384 < cert-p384.json
cat cert-p384.pem subca.pem > cert-p384.chained.pem

# FIXME: generate *.der.b64
# FIXME: extract serial number in decimal representation to file and refer from tests
