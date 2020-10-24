# Projet de Sécurité : Attaque par oracle sur AES

* [Page du projet](https://cmaurice.fr/teaching/ENS/project6.html)
* [Article introductif](https://research.checkpoint.com/2019/cryptographic-attacks-a-guide-for-the-perplexed/)
* [Wiki OpenSSL](https://wiki.openssl.org/index.php/Enc)

## Utilisation d'AES (via OpenSSL)

### Chiffrer avec AES
`openssl enc -e -aes-128-cbc -in msg.txt -out enc.txt -iv 12345678901234567890123456789012 -K 23456789012345678901234567890123`

### Déchiffrer avec AES
`openssl enc -d -aes-128-cbc -in enc.txt -iv 12345678901234567890123456789012 -K 23456789012345678901234567890123`

![Fonctionnement du chiffrement](cbc-enc.png)

![Fonctionnement du déchiffrement](cbc-dec.png)
