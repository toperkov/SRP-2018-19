
# Crypto challenge - Simetrična kriptografija

U sklopu današnje vježbe student će morati riješiti *crypto challenge*. Rješenje se može realizirati u bilo kojem programskom jeziku, ali preporučujemo korištenje ``python`` programskog okruženja. Ova vježba upoznaje studente sa osnovama **simetrične kriptografije**, točnije za blok šiframa fiksne duljine koji se danas koriste u većini modernih kriptografskih sustava.

Jedna od najpopularnijih ekripcijskih algoritama koji implementira blok šifre fiksne duljine je **AES** algoritam, te podupire rad s blokovima duljine 128 bitova i ključevima duljine 128, 192 i 256 bitova. Blok šifra u osnovi "razbije" ulaznu poruku u seriju sekvencijalnih blokova odgovarajuće dužine (npr. 128 bita), te procesira ove blokove po principu "jedan po jedan". Kod **AES-CBC** enkripcijskog moda plantext blokovi ulančavaju (eng. *chaining*) kako je prikazano na slici u nastavku.

<p align="center">
  <img width="500" src="https://raw.githubusercontent.com/mcagalj/CNS-2017-18/master/img/cbc.PNG">
</p>

Zadatak studenta je dešifrirati tekst/vic enkriptiran **AES** šifrom u **CBC** enkripcijskom modu. Za svakog studenta je kreirana datoteka u direktoriju [Studenti](Studenti) na github repozitoriju koja sadrži šifrirani tekst. Kako bi student znao koja datoteka njemu pripada naziv datoteke je kreirano korištenjem kriptografske hash funkcije **SHA-256** na sljedeći način:


```python
hash("PerkovicToni" + "SALT") = f3f496e59923ea2f120edbe0b603fac4719bb01e250e9534e401af6f1edb0a5e
```

gdje je ``SALT`` vrijednost koju će vam profesori dati na vježbama. **NAPOMENA:** Primjetite kako nema razmaka između prezimena i imena te nisu korištena HR slova (čćžšđ) dok je ime studenta formatirano po principu ``PrezimeIme``. Da biste saznali ime datoteke koje pripada svakom studentu, u python okruženju napravite sljedeće:

```python
>>> from cryptography.hazmat.primitives import hashes
>>> from cryptography.hazmat.backends import default_backend
>>> imeStudenta = "PerkovicToni" + "SALT" # NAPOMENA: SALT dobivate od profesora
>>> digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
>>> digest.update(str.encode(imeStudenta))
>>> filename = digest.finalize().hex()
>>> print(filename)
```

Nadalje, za ekpripciju teksta kreirana je funkcija ``encrypt`` koja uzima 128 bitni inicijalizacijski vektor (``iv``), odgovarajući *plaintext* (``QUOTE``) te ga šifrira algoritmom **AES** u **CBC** modu tajnim 256 bitnim ključem (32 byte-a) i vraća vam odgovarajući ciphertext (``enc``).

```python
key = os.urandom(KEY_BLOCK_SIZE)
iv = os.urandom(IV_BLOCK_SIZE)
enc = encrypt(key, iv, str.encode(QUOTE))
```

## Zadatak

U nastavku se nalazi jednostavan python modul ``encrypt_lab2.py`` koji je korišten za šifriranje teksta/vica. Vaš zadatak je razumijeti kod za šifriranje koji je dan u nastavku, te kreirati modul (skriptu) koja će dešifrirati tekst koji se nalazi u datoteci u direktoriju [Studenti](Studenti). **HINT:** Za potrebe rada s kriptografskim primitivima (enkripcijskim algoritmima te kriptografskim hash funkcijama) koristili smo Python paket [cryptography](https://cryptography.io), koji nudi objašnjenje korištenja kriptografskih primitiva sa primjerima (receptima).

```python
# file encrypt_lab2.py

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives import (
	hashes,
	padding
)
from cryptography.hazmat.backends import default_backend
import os
import base64


KEY_BLOCK_SIZE = 32
CIPHER_BLOCK_LENGTH = 128
IV_BLOCK_SIZE = 16
CIPHER = algorithms.AES

STUDENTNAME = "PerkovicToni" # ne koriste se HR slova (čćžšđ)
SALT = "!ASK_PROFESSOR!" # pitajte profesora na vježbama

QUOTE = "The lock on the old door could only take short keys"


def encrypt(key, iv, plaintext):
    ''' Function encrypt '''

    padder = padding.PKCS7(CIPHER_BLOCK_LENGTH).padder()
    padded_plaintext = padder.update(plaintext)
    padded_plaintext += padder.finalize()

    cipher = Cipher(CIPHER(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext)
    ciphertext += encryptor.finalize()

    return ciphertext


if __name__ =='__main__':

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(str.encode(STUDENTNAME + SALT))
    filename = digest.finalize().hex()

    key = os.urandom(KEY_BLOCK_SIZE)
    iv = os.urandom(IV_BLOCK_SIZE)
    enc = encrypt(key, iv, str.encode(QUOTE))

    f_out = open(filename + ".enc", 'wb')
    f_out.write(key)
    f_out.write(iv)
    f_out.write(enc)
    f_out.close()
```
