# Commandes OpenSSL — PKI à Trois Niveaux

## 1. Initialisation de la structure
mkdir C:\PKI\root-ca\private root-ca\certs root-ca\crl root-ca\newcerts
mkdir C:\PKI\intermediate-ca\private intermediate-ca\certs intermediate-ca\crl intermediate-ca\csr
mkdir C:\PKI\leaf\private leaf\certs leaf\csr

type nul > C:\PKI\root-ca\index.txt
echo 1000 > C:\PKI\root-ca\serial
echo 1000 > C:\PKI\root-ca\crlnumber
type nul > C:\PKI\intermediate-ca\index.txt
echo 2000 > C:\PKI\intermediate-ca\serial
echo 2000 > C:\PKI\intermediate-ca\crlnumber

## 2. Root CA — Clé privée RSA 4096
openssl genrsa -aes256 -out C:\PKI\root-ca\private\root-ca.key.pem 4096

## 3. Root CA — Certificat auto-signé
openssl req -config C:\PKI\root-ca\openssl-root.cnf -key C:\PKI\root-ca\private\root-ca.key.pem -new -x509 -days 3650 -sha256 -extensions v3_ca -out C:\PKI\root-ca\certs\root-ca.cert.pem

## 4. Root CA — Vérification
openssl x509 -noout -text -in C:\PKI\root-ca\certs\root-ca.cert.pem

## 5. Intermediate CA — Clé privée RSA 2048
openssl genrsa -aes256 -out C:\PKI\intermediate-ca\private\intermediate-ca.key.pem 2048

## 6. Intermediate CA — Génération du CSR
openssl req -config C:\PKI\intermediate-ca\openssl-intermediate.cnf -new -sha256 -key C:\PKI\intermediate-ca\private\intermediate-ca.key.pem -out C:\PKI\intermediate-ca\csr\intermediate-ca.csr.pem

## 7. Intermediate CA — Signature par la Root CA
openssl ca -config C:\PKI\root-ca\openssl-root.cnf -extensions v3_intermediate_ca -days 1825 -notext -md sha256 -in C:\PKI\intermediate-ca\csr\intermediate-ca.csr.pem -out C:\PKI\intermediate-ca\certs\intermediate-ca.cert.pem

## 8. Création de la chaîne de confiance
type C:\PKI\intermediate-ca\certs\intermediate-ca.cert.pem C:\PKI\root-ca\certs\root-ca.cert.pem > C:\PKI\intermediate-ca\certs\ca-chain.cert.pem

## 9. Vérification de la chaîne
openssl verify -CAfile C:\PKI\root-ca\certs\root-ca.cert.pem C:\PKI\intermediate-ca\certs\intermediate-ca.cert.pem

## 10. Leaf Certificate — Clé privée
openssl genrsa -out C:\PKI\leaf\private\server.key.pem 2048

## 11. Leaf Certificate — CSR
openssl req -config C:\PKI\intermediate-ca\openssl-intermediate.cnf -key C:\PKI\leaf\private\server.key.pem -new -sha256 -out C:\PKI\leaf\csr\server.csr.pem

## 12. Leaf Certificate — Signature par Intermediate CA
openssl ca -config C:\PKI\intermediate-ca\openssl-intermediate.cnf -extensions server_cert -days 365 -notext -md sha256 -in C:\PKI\leaf\csr\server.csr.pem -out C:\PKI\leaf\certs\server.cert.pem

## 13. Vérification du certificat final
openssl verify -CAfile C:\PKI\intermediate-ca\certs\ca-chain.cert.pem C:\PKI\leaf\certs\server.cert.pem

## 14. Génération CRL Root CA
openssl ca -config C:\PKI\root-ca\openssl-root.cnf -gencrl -out C:\PKI\root-ca\crl\root-ca.crl.pem

## 15. Génération CRL Intermediate CA
openssl ca -config C:\PKI\intermediate-ca\openssl-intermediate.cnf -gencrl -out C:\PKI\intermediate-ca\crl\intermediate-ca.crl.pem

## 16. Révocation d'un certificat
openssl ca -config C:\PKI\intermediate-ca\openssl-intermediate.cnf -revoke C:\PKI\leaf\certs\server.cert.pem