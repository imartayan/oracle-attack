# Attaques par oracle sur AES et RSA

Ce projet a été réalisé avec [Manon Sourisseau](https://github.com/ManonLittleMouse) dans le cadre du module de [sécurité](https://cmaurice.fr/teaching/ENS/) de l'[ENS Rennes](http://www.ens-rennes.fr/).
Il est licencié selon les termes de la licence GPLv3.

## Prérequis

Ce projet nécessite une version récente de Python 3 (au moins 3.6) ainsi que la bibliothèque [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/api.html) (`pip install pycryptodome`).

## Attaque de Vaudenay sur AES

```
usage: python3 vaudenay.py [-h] [-iv IV] [-k KEY] [-s SIZE] [-e] file

Python implementation of Vaudenay's oracle attack on AES-128-CBC

positional arguments:
  file                  file containing the (encrypted) message

optional arguments:
  -h, --help            show this help message and exit
  -iv IV                initialization vector
  -k KEY, --key KEY     secret key used for encryption/decryption
  -s SIZE, --size SIZE  AES block size in bits (128 by default)
  -e, --encrypt         encrypt the message with iv and secret key
```

### Utiliser OpenSSL pour (dé)chiffrer avec AES

#### Chiffrer un fichier
`openssl enc -e -aes-128-cbc -in SOURCE_FILE -out ENCRYPTED_FILE -iv INITIALIZATION_VECTOR -K SECRET_KEY`

#### Déchiffrer un fichier
`openssl enc -d -aes-128-cbc -in ENCRYPTED_FILE -iv INITIALIZATION_VECTOR -K SECRET_KEY`

## Attaque de Bleichenbacher sur RSA

```
usage: python3 bleichenbacher.py [-h] [-k KEY] [-e] file

Python implementation of Bleichenbacher's oracle attack on RSA PKCS#1 v1.5

positional arguments:
  file               file containing the (encrypted) message

optional arguments:
  -h, --help         show this help message and exit
  -k KEY, --key KEY  file containing the private key
  -e, --encrypt      encrypt the message with private key
```

## Quelques liens

* [Page du projet](https://cmaurice.fr/teaching/ENS/project6.html)
* [Article introductif](https://research.checkpoint.com/2019/cryptographic-attacks-a-guide-for-the-perplexed/)
* [Article de Vaudenay](https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf)
* [Article de Bleichenbacher](http://archiv.infsec.ethz.ch/education/fs08/secsem/Bleichenbacher98.pdf)
* [Documentation de PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/api.html)
* [Wiki OpenSSL](https://wiki.openssl.org/index.php/Enc)
