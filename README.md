# PKI Infrastructure à Trois Niveaux

## Description
Implémentation d'une Infrastructure à Clés Publiques (PKI) à trois niveaux.
Master MMSD — Module Cryptographie et Blockchain 2024/2025.

## Architecture
- **Root CA** : Autorité racine auto-signée (RSA 4096 bits, 10 ans)
- **Intermediate CA** : Autorité intermédiaire (RSA 2048 bits, 5 ans)
- **Leaf Certificates** : Certificats serveur/client (RSA 2048 bits, 1 an)

## Technologies
- OpenSSL 3.x
- Python 3.x / Flask
- HTML / CSS / JavaScript

## Lancement
```bash
pip install flask
python app.py
```
Accès : http://localhost:5001

## Fonctionnalités
- Création Root CA et Intermediate CA
- Émission de certificats serveur et client
- Révocation et génération des CRL
- Vérification de la chaîne de confiance
- Interface web complète

## Encadrante
Pr. LECHHAB OUADRASSI Nihad
