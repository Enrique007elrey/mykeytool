"""Guarda y abre el almacén de claves cifrado con una contraseña.

El almacén es un diccionario de Python:
    { "alias": {"dn": {...datos del titular...}, "key": "clave privada cifrada"} }

En el archivo se guarda así, todo en binario (no se ve ningún texto):
    [ salt (16 bytes) ][ diccionario en JSON cifrado con Fernet, en bytes ]

Fernet entrega el resultado escrito en Base64. Para que en el archivo no se
vea nada legible, quitamos ese Base64 al guardar y lo volvemos a poner al leer.
"""

import base64
import json
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from errors import KeystoreCorruptError, KeystoreNotFoundError, WrongPasswordError

KEYSTORE_FILE = "keystore.dat"


def password_to_key(password, salt):
    """Convierte la contraseña en una clave para Fernet usando PBKDF2."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def exists():
    return os.path.isfile(KEYSTORE_FILE)


def load(password):
    """Abre el almacén y devuelve el diccionario con las entradas."""
    if not exists():
        raise KeystoreNotFoundError("El almacén no existe. Créalo con --genkeypair.")

    with open(KEYSTORE_FILE, "rb") as f:
        data = f.read()
    if len(data) < 17:
        raise KeystoreCorruptError("El almacén está dañado.")

    salt = data[:16]        # los primeros 16 bytes son el salt
    # El resto son los datos cifrados en binario; Fernet los necesita en Base64
    encrypted = base64.urlsafe_b64encode(data[16:])

    try:
        decrypted = Fernet(password_to_key(password, salt)).decrypt(encrypted)
    except InvalidToken:
        # Fernet no puede descifrar: la contraseña no es la correcta
        raise WrongPasswordError("Contraseña del almacén incorrecta (o el archivo está dañado).")

    try:
        return json.loads(decrypted)
    except json.JSONDecodeError:
        raise KeystoreCorruptError("El almacén está dañado.")


def save(entries, password):
    """Cifra el diccionario y lo guarda en el archivo."""
    salt = os.urandom(16)   # salt aleatorio nuevo cada vez
    token = Fernet(password_to_key(password, salt)).encrypt(json.dumps(entries).encode())
    encrypted = base64.urlsafe_b64decode(token)   # quitamos el Base64: solo bytes cifrados
    with open(KEYSTORE_FILE, "wb") as f:
        f.write(salt + encrypted)