"""Simulador de Java keytool en Python - programa principal.

Tiene los mismos comandos que 'keytool -help'. Los comandos valen con un guion
(-genkeypair, como en Java) o con dos (--genkeypair).

Tipos de entrada que se guardan en el almacén (como en el keytool real):
  - PrivateKeyEntry:  par de claves RSA + datos del titular   (-genkeypair)
  - SecretKeyEntry:   clave secreta AES o contraseña guardada  (-genseckey, -importpass)
  - trustedCertEntry: certificado de otra persona o de una CA  (-importcert)
"""
import argparse
import base64
import getpass
import hashlib
import os
import platform
import sys
from datetime import datetime, timedelta, timezone

import cryptography
from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization

import crypto_utils
import keystore
from errors import (AliasExistsError, AliasNotFoundError, InvalidInputError,
                    KeystoreNotFoundError, KeytoolError, WrongPasswordError)

MAX_INTENTOS = 3                 # intentos para escribir bien una contraseña
TAMANOS_CLAVE = (2048, 4096)     # bits que se pueden elegir para la clave RSA
TAMANOS_AES = (128, 256)         # bits que se pueden elegir para la clave secreta
SI = ("s", "si", "sí", "yes", "y")

# Campos del titular (Distinguished Name) y la pregunta de cada uno
CAMPOS_DN = [
    ("CN", "Nombre y apellidos"),
    ("OU", "Unidad organizativa"),
    ("O", "Organización"),
    ("L", "Ciudad"),
    ("ST", "Provincia"),
    ("C", "País, 2 letras"),
]


# ---------- Funciones para pedir datos ----------

def ask_new_password(texto="Nueva contraseña del almacén: "):
    """Pide una contraseña nueva dos veces y comprueba que coinciden."""
    password = getpass.getpass(texto)
    repeat = getpass.getpass("Repite la contraseña: ")
    if password != repeat:
        raise InvalidInputError("Las contraseñas no coinciden.")
    if len(password) < 6:
        raise InvalidInputError("La contraseña debe tener al menos 6 caracteres.")
    return password


def open_keystore():
    """Pide la contraseña del almacén (hasta 3 intentos) y lo abre.
    Devuelve el diccionario de entradas y la contraseña."""
    if not keystore.exists():
        raise KeystoreNotFoundError()
    for intento in range(1, MAX_INTENTOS + 1):
        password = getpass.getpass("Contraseña del almacén: ")
        try:
            return keystore.load(password), password
        except WrongPasswordError:
            quedan = MAX_INTENTOS - intento
            if quedan == 0:
                raise WrongPasswordError(f"Contraseña del almacén incorrecta {MAX_INTENTOS} veces. Acceso bloqueado.")
            print(f"Contraseña incorrecta. Te quedan {quedan} intento(s).")


def open_or_create_keystore():
    """Abre el almacén, o lo crea si todavía no existe (como hace keytool)."""
    if keystore.exists():
        return open_keystore()
    print("El almacén no existe, se va a crear uno nuevo.")
    return {}, ask_new_password()


def ask_existing_alias(entries, texto="Alias: ", tipos=None):
    """Pide un alias que exista. Con 'tipos' se exige además un tipo de entrada."""
    alias = input(texto).strip().lower()
    if alias not in entries:
        raise AliasNotFoundError(f"El alias '{alias}' no existe.")
    if tipos and entry_type(entries[alias]) not in tipos:
        raise InvalidInputError(f"El alias '{alias}' es de tipo {entry_type(entries[alias])} "
                                f"y este comando necesita {' o '.join(tipos)}.")
    return alias


def ask_new_alias(entries, texto="Alias: "):
    """Pide un alias nuevo y comprueba que no esté repetido."""
    alias = input(texto).strip().lower()
    if not alias:
        raise InvalidInputError("El alias no puede estar vacío.")
    if alias in entries:
        raise AliasExistsError(f"El alias '{alias}' ya existe.")
    return alias


def ask_alias_password(store_pass):
    """Pide la contraseña del alias nuevo. Si se pulsa Enter, se usa la del almacén."""
    key_pass = getpass.getpass("Contraseña del alias (Enter = la misma del almacén): ")
    if key_pass == "":
        return store_pass
    if getpass.getpass("Repite la contraseña del alias: ") != key_pass:
        raise InvalidInputError("Las contraseñas del alias no coinciden.")
    if len(key_pass) < 6:
        raise InvalidInputError("La contraseña del alias debe tener al menos 6 caracteres.")
    return key_pass


def with_alias_password(store_pass, abrir):
    """Pide la contraseña del alias (hasta 3 intentos) y llama a abrir(contraseña).
    Devuelve lo que devuelva abrir() y la contraseña que ha funcionado."""
    for intento in range(1, MAX_INTENTOS + 1):
        key_pass = getpass.getpass("Contraseña del alias (Enter = la misma del almacén): ")
        if key_pass == "":
            key_pass = store_pass
        try:
            return abrir(key_pass), key_pass
        except WrongPasswordError:
            quedan = MAX_INTENTOS - intento
            if quedan == 0:
                raise WrongPasswordError(f"Contraseña del alias incorrecta {MAX_INTENTOS} veces. Acceso bloqueado.")
            print(f"Contraseña incorrecta. Te quedan {quedan} intento(s).")


def unlock_private_key(entry, store_pass):
    """Descifra la clave privada de una PrivateKeyEntry (hasta 3 intentos)."""
    clave, _ = with_alias_password(
        store_pass, lambda pw: crypto_utils.decrypt_private_key(entry["key"], pw))
    return clave


def dn_for_cert(dn):
    """Prepara el DN para el certificado: el país "None" no se incluye,
    porque en un certificado el país tiene que tener 2 letras."""
    datos = dict(dn)
    if datos.get("C", "None") == "None":
        datos["C"] = ""
    return datos


def ask_dn():
    """Pide los datos del titular. Si se pulsa Enter, el campo queda como None.
    Al final enseña un resumen y pregunta si es correcto (si no, se repite)."""
    while True:
        print("Datos del titular (Enter = None):")
        dn = {}
        for clave, pregunta in CAMPOS_DN:
            valor = input(f"  {pregunta} ({clave}): ").strip()
            dn[clave] = valor if valor else "None"
        if dn["C"] != "None":
            dn["C"] = dn["C"].upper()

        # Comprobamos que los datos sirven para un certificado (país de 2 letras...)
        try:
            crypto_utils.build_name(dn_for_cert(dn))
        except ValueError as e:
            print(f"Error: {e} Vuelve a escribir los datos.\n")
            continue

        # Revisión: enseñamos lo que ha escrito y preguntamos si está bien
        resumen = ", ".join(f"{clave}={valor}" for clave, valor in dn.items())
        respuesta = input(f"¿Es correcto {resumen}? (s/n): ").strip().lower()
        if respuesta in SI:
            return dn
        print("Vale, vuelve a escribir los datos.\n")


def ask_size(texto, opciones):
    """Pregunta un tamaño de clave entre las opciones (Enter = la primera)."""
    while True:
        valor = input(texto).strip()
        if valor == "":
            return opciones[0]
        if valor.isdigit() and int(valor) in opciones:
            return int(valor)
        print(f"Solo se puede elegir {' o '.join(str(o) for o in opciones)}.")


def ask_file(texto):
    """Pide el nombre de un archivo y comprueba que existe."""
    nombre = input(texto).strip().strip('"')
    if not os.path.isfile(nombre):
        raise InvalidInputError(f"El archivo '{nombre}' no existe.")
    with open(nombre, "rb") as f:
        return nombre, f.read()


# ---------- Utilidades criptográficas ----------

def entry_type(entry):
    """Tipo de una entrada. Las creadas antes de añadir tipos son PrivateKeyEntry."""
    return entry.get("type", "PrivateKeyEntry")


def fingerprint(datos_der):
    """Huella SHA-256 en formato AA:BB:CC..., como la muestra keytool."""
    resumen = hashlib.sha256(datos_der).hexdigest().upper()
    return ":".join(resumen[i:i + 2] for i in range(0, len(resumen), 2))


def sha256_fingerprint(public_key_pem):
    """Huella SHA-256 de una clave pública guardada en PEM."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return fingerprint(der)


def public_key_pem(private_key):
    """Clave pública de una clave privada, en PEM (texto)."""
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def encrypt_secret(datos, password):
    """Cifra un secreto (clave AES o contraseña) con la contraseña del alias.
    Igual que el almacén: PBKDF2 con un salt aleatorio y luego Fernet."""
    salt = os.urandom(16)
    token = Fernet(keystore.password_to_key(password, salt)).encrypt(datos)
    return base64.b64encode(salt).decode() + ":" + token.decode()


def decrypt_secret(cifrado, password):
    """Descifra un secreto guardado con encrypt_secret."""
    salt_b64, token = cifrado.split(":", 1)
    try:
        return Fernet(keystore.password_to_key(password, base64.b64decode(salt_b64))).decrypt(token.encode())
    except InvalidToken:
        raise WrongPasswordError("Contraseña del alias incorrecta.")


def unlock_entry(entry, password):
    """Abre la parte secreta de cualquier entrada (clave privada o secreto)."""
    if entry_type(entry) == "PrivateKeyEntry":
        return crypto_utils.decrypt_private_key(entry["key"], password)
    return decrypt_secret(entry["key"], password)


def self_signed_cert(private_key, dn, dias=365):
    """Certificado autofirmado: el emisor y el titular son la misma persona."""
    name = crypto_utils.build_name(dn_for_cert(dn))
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=dias))
        .sign(private_key, hashes.SHA256())
    )


def load_cert(datos):
    """Carga un certificado en PEM o en DER."""
    try:
        if datos.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_certificate(datos)
        return x509.load_der_x509_certificate(datos)
    except ValueError:
        raise InvalidInputError("El archivo no es un certificado válido.")


def describe_cert(cert):
    """Datos de un certificado, con el formato de 'keytool -printcert'."""
    return "\n".join([
        f"Propietario: {cert.subject.rfc4514_string()}",
        f"Emisor: {cert.issuer.rfc4514_string()}",
        f"Número de serie: {cert.serial_number:x}",
        f"Válido desde: {cert.not_valid_before_utc:%d/%m/%Y %H:%M} UTC "
        f"hasta: {cert.not_valid_after_utc:%d/%m/%Y %H:%M} UTC",
        "Huellas digitales del certificado:",
        f"\t SHA256: {fingerprint(cert.public_bytes(serialization.Encoding.DER))}",
        f"Algoritmo de firma: {cert.signature_hash_algorithm.name.upper()}withRSA",
        f"Clave pública: RSA de {cert.public_key().key_size} bits",
    ])


# ---------- Comandos ----------

def cmd_genkeypair():
    """-genkeypair: genera un par de claves RSA."""
    entries, store_pass = open_or_create_keystore()
    alias = ask_new_alias(entries)
    key_pass = ask_alias_password(store_pass)          # antes que los datos, como keytool
    dn = ask_dn()
    key_size = ask_size("Tamaño de la clave RSA en bits (2048 o 4096, Enter = 2048): ", TAMANOS_CLAVE)

    print(f"Generando clave RSA de {key_size} bits...")
    private_key = crypto_utils.generate_rsa_keypair(key_size)
    entries[alias] = {
        "type": "PrivateKeyEntry",
        "dn": dn,
        "key_size": key_size,
        "key": crypto_utils.encrypt_private_key(private_key, key_pass),
        "public_key": public_key_pem(private_key),
    }
    keystore.save(entries, store_pass)
    print(f"Clave '{alias}' guardada en {keystore.KEYSTORE_FILE}.")


def cmd_genseckey():
    """-genseckey: genera una clave secreta AES (criptografía simétrica)."""
    entries, store_pass = open_or_create_keystore()
    alias = ask_new_alias(entries)
    key_pass = ask_alias_password(store_pass)
    bits = ask_size("Tamaño de la clave AES en bits (128 o 256, Enter = 128): ", TAMANOS_AES)

    print(f"Generando clave secreta AES de {bits} bits...")
    clave = os.urandom(bits // 8)                      # bytes aleatorios = clave AES
    entries[alias] = {
        "type": "SecretKeyEntry",
        "algorithm": "AES",
        "key_size": bits,
        "key": encrypt_secret(clave, key_pass),
    }
    keystore.save(entries, store_pass)
    print(f"Clave secreta '{alias}' guardada en {keystore.KEYSTORE_FILE}.")


def cmd_importpass():
    """-importpass: guarda una contraseña en el almacén, protegida."""
    entries, store_pass = open_or_create_keystore()
    alias = ask_new_alias(entries)
    secreto = getpass.getpass("Contraseña que se va a guardar: ")
    if getpass.getpass("Repite la contraseña: ") != secreto:
        raise InvalidInputError("Las contraseñas no coinciden.")
    if not secreto:
        raise InvalidInputError("La contraseña no puede estar vacía.")
    key_pass = ask_alias_password(store_pass)

    entries[alias] = {
        "type": "SecretKeyEntry",
        "algorithm": "PBE",
        "key_size": len(secreto.encode()) * 8,
        "key": encrypt_secret(secreto.encode(), key_pass),
    }
    keystore.save(entries, store_pass)
    print(f"Contraseña guardada en el alias '{alias}'.")


def cmd_certreq():
    """-certreq: genera una solicitud de certificado (CSR)."""
    entries, store_pass = open_keystore()
    alias = ask_existing_alias(entries, tipos=("PrivateKeyEntry",))
    private_key = unlock_private_key(entries[alias], store_pass)

    name = crypto_utils.build_name(dn_for_cert(entries[alias]["dn"]))
    csr = crypto_utils.create_csr(private_key, name)
    filename = f"{alias}.csr"
    with open(filename, "wb") as f:
        f.write(csr)
    print(f"CSR guardada en {filename}.")


def cmd_gencert():
    """-gencert: firma una solicitud (CSR) con la clave de un alias y crea el certificado.
    Así el alias hace de Autoridad de Certificación (CA)."""
    entries, store_pass = open_keystore()
    alias = ask_existing_alias(entries, "Alias que firma (el emisor): ", ("PrivateKeyEntry",))
    private_key = unlock_private_key(entries[alias], store_pass)

    nombre, datos = ask_file("Archivo de la solicitud (.csr): ")
    try:
        csr = x509.load_pem_x509_csr(datos)
    except ValueError:
        raise InvalidInputError("El archivo no es una solicitud CSR válida.")
    if not csr.is_signature_valid:
        raise InvalidInputError("La firma de la CSR no es válida: no se puede emitir el certificado.")

    emisor = crypto_utils.build_name(dn_for_cert(entries[alias]["dn"]))
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)          # el titular es quien pidió el certificado
        .issuer_name(emisor)                # el emisor es el alias que firma
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    salida = os.path.splitext(nombre)[0] + "_firmado.crt"
    with open(salida, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Certificado emitido por '{alias}' y guardado en {salida}.")


def cmd_importcert():
    """-importcert: guarda en el almacén un certificado de confianza."""
    nombre, datos = ask_file("Archivo del certificado (.crt): ")
    cert = load_cert(datos)
    entries, store_pass = open_or_create_keystore()
    alias = ask_new_alias(entries)

    print(describe_cert(cert))
    if input("¿Confiar en este certificado? (s/n): ").strip().lower() not in SI:
        print("No se ha importado el certificado.")
        return
    entries[alias] = {
        "type": "trustedCertEntry",
        "cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
    }
    keystore.save(entries, store_pass)
    print(f"Certificado agregado al almacén con el alias '{alias}'.")


def cmd_importkeystore():
    """-importkeystore: copia las entradas de otro almacén a este."""
    origen = input("Archivo del almacén de origen: ").strip().strip('"')
    if not keystore.exists(origen):
        raise KeystoreNotFoundError(f"El almacén '{origen}' no existe.")
    if os.path.abspath(origen) == os.path.abspath(keystore.KEYSTORE_FILE):
        raise InvalidInputError("El almacén de origen y el de destino son el mismo.")
    entradas_origen = keystore.load(getpass.getpass("Contraseña del almacén de origen: "), origen)

    print("Almacén de destino:")
    entries, store_pass = open_or_create_keystore()
    copiadas = 0
    for alias, entry in entradas_origen.items():
        if alias in entries:
            print(f"  - '{alias}' ya existe en el destino: no se copia.")
        else:
            entries[alias] = entry
            copiadas += 1
            print(f"  - '{alias}' importado.")
    keystore.save(entries, store_pass)
    print(f"Se han importado {copiadas} de {len(entradas_origen)} entrada(s).")


def cmd_list():
    """-list: muestra las entradas del almacén con su huella SHA-256."""
    entries, _ = open_keystore()
    print("Tipo de almacén: MYKS (keystore.dat)")
    print(f"Su almacén de claves contiene {len(entries)} entrada(s)\n")
    for alias, entry in entries.items():
        tipo = entry_type(entry)
        print(f"Alias: {alias}")
        print(f"  Tipo de entrada: {tipo}")
        if tipo == "PrivateKeyEntry":
            print(f"  Titular: {entry['dn']['CN']}")
            print(f"  Tamaño: RSA de {entry.get('key_size', 2048)} bits")
            if "public_key" in entry:
                print(f"  Huella SHA-256: {sha256_fingerprint(entry['public_key'])}")
            else:
                print("  Huella SHA-256: no disponible (clave creada con una versión anterior)")
        elif tipo == "SecretKeyEntry":
            print(f"  Algoritmo: {entry['algorithm']} ({entry['key_size']} bits)")
        else:
            cert = load_cert(entry["cert"].encode())
            print(f"  Propietario: {cert.subject.rfc4514_string()}")
            print(f"  Huella SHA-256: {fingerprint(cert.public_bytes(serialization.Encoding.DER))}")
        print()


def cmd_delete():
    """-delete: borra una entrada."""
    entries, store_pass = open_keystore()
    alias = ask_existing_alias(entries, "Alias a borrar: ")
    del entries[alias]
    keystore.save(entries, store_pass)
    print(f"Alias '{alias}' borrado.")


def cmd_changealias():
    """-changealias: cambia el nombre de un alias sin tocar sus claves."""
    entries, store_pass = open_keystore()
    viejo = ask_existing_alias(entries, "Alias actual: ")
    nuevo = ask_new_alias(entries, "Nuevo alias: ")
    entries[nuevo] = entries.pop(viejo)
    keystore.save(entries, store_pass)
    print(f"Alias '{viejo}' cambiado a '{nuevo}'.")


def cmd_exportcert():
    """-exportcert: exporta el certificado de un alias a un archivo .crt."""
    entries, store_pass = open_keystore()
    alias = ask_existing_alias(entries, "Alias a exportar: ", ("PrivateKeyEntry", "trustedCertEntry"))
    entry = entries[alias]
    if entry_type(entry) == "trustedCertEntry":
        datos = entry["cert"].encode()                    # ya es un certificado
    else:
        private_key = unlock_private_key(entry, store_pass)
        datos = self_signed_cert(private_key, entry["dn"]).public_bytes(serialization.Encoding.PEM)
    filename = f"{alias}.crt"
    with open(filename, "wb") as f:
        f.write(datos)
    print(f"Certificado guardado en {filename} (sin la clave privada).")


def cmd_keypasswd():
    """-keypasswd: cambia la contraseña de un alias."""
    entries, store_pass = open_keystore()
    alias = ask_existing_alias(entries, tipos=("PrivateKeyEntry", "SecretKeyEntry"))
    entry = entries[alias]
    print("Contraseña actual del alias:")
    secreto, _ = with_alias_password(store_pass, lambda pw: unlock_entry(entry, pw))
    nueva = ask_new_password("Nueva contraseña del alias: ")
    if entry_type(entry) == "PrivateKeyEntry":
        entry["key"] = crypto_utils.encrypt_private_key(secreto, nueva)
    else:
        entry["key"] = encrypt_secret(secreto, nueva)
    keystore.save(entries, store_pass)
    print(f"Contraseña del alias '{alias}' cambiada.")


def cmd_storepasswd():
    """-storepasswd: cambia la contraseña del almacén (lo vuelve a cifrar)."""
    entries, _ = open_keystore()
    nueva = ask_new_password()
    keystore.save(entries, nueva)
    print("Contraseña del almacén cambiada.")


def cmd_printcert():
    """-printcert: muestra el contenido de un certificado (.crt)."""
    _, datos = ask_file("Archivo del certificado (.crt): ")
    print(describe_cert(load_cert(datos)))


def cmd_printcertreq():
    """-printcertreq: muestra el contenido de una solicitud (.csr)."""
    _, datos = ask_file("Archivo de la solicitud (.csr): ")
    try:
        csr = x509.load_pem_x509_csr(datos)
    except ValueError:
        raise InvalidInputError("El archivo no es una solicitud CSR válida.")
    print(f"Propietario: {csr.subject.rfc4514_string()}")
    print(f"Clave pública: RSA de {csr.public_key().key_size} bits")
    print(f"Algoritmo de firma: {csr.signature_hash_algorithm.name.upper()}withRSA")
    print(f"Firma válida: {'Sí' if csr.is_signature_valid else 'NO'}")


def cmd_printcrl():
    """-printcrl: muestra una lista de revocación de certificados (CRL)."""
    _, datos = ask_file("Archivo de la lista de revocación (.crl): ")
    try:
        if datos.lstrip().startswith(b"-----BEGIN"):
            crl = x509.load_pem_x509_crl(datos)
        else:
            crl = x509.load_der_x509_crl(datos)
    except ValueError:
        raise InvalidInputError("El archivo no es una CRL válida.")
    print(f"Emisor: {crl.issuer.rfc4514_string()}")
    print(f"Última actualización: {crl.last_update_utc:%d/%m/%Y %H:%M} UTC")
    if crl.next_update_utc:
        print(f"Próxima actualización: {crl.next_update_utc:%d/%m/%Y %H:%M} UTC")
    revocados = list(crl)
    print(f"Certificados revocados: {len(revocados)}")
    for r in revocados:
        print(f"  - Nº de serie {r.serial_number:x}, revocado el {r.revocation_date_utc:%d/%m/%Y}")


def cmd_showinfo():
    """-showinfo: información de seguridad del simulador."""
    print("Información de seguridad de mykeytool")
    print(f"  Python: {platform.python_version()} ({sys.platform})")
    print(f"  Librería cryptography: {cryptography.__version__}")
    print(f"  Almacén: {keystore.KEYSTORE_FILE} (binario, cifrado)")
    print("  Cifrado del almacén: Fernet (AES-128-CBC + HMAC-SHA256)")
    print("  Clave del almacén: PBKDF2-HMAC-SHA256, 600.000 iteraciones, salt de 16 bytes")
    print("  Claves privadas: RSA de 2048 o 4096 bits, cifradas con la contraseña del alias (PKCS8)")
    print("  Claves secretas: AES de 128 o 256 bits")
    print("  Firmas (CSR y certificados): SHA256withRSA")
    print(f"  Intentos de contraseña: {MAX_INTENTOS}")


# ---------- Ayuda (igual que la del keytool de Java) ----------

# Cada comando: (nombre, función, descripción corta, qué pide)
COMANDOS = [
    ("certreq", cmd_certreq, "Genera una solicitud de certificado",
     "Pide la contraseña del almacén, el alias y la contraseña del alias.\n"
     "Crea el archivo <alias>.csr en formato PEM, firmado con SHA-256."),
    ("changealias", cmd_changealias, "Cambia el alias de una entrada",
     "Pide la contraseña del almacén, el alias actual y el nuevo alias."),
    ("delete", cmd_delete, "Suprime una entrada",
     "Pide la contraseña del almacén y el alias que se quiere borrar."),
    ("exportcert", cmd_exportcert, "Exporta el certificado",
     "Pide la contraseña del almacén, el alias y la contraseña del alias.\n"
     "Crea el archivo <alias>.crt (sin la clave privada)."),
    ("genkeypair", cmd_genkeypair, "Genera un par de claves",
     "Pide la contraseña del almacén (lo crea si no existe), el alias,\n"
     "la contraseña del alias, los datos del titular (CN, OU, O, L, ST, C)\n"
     "y el tamaño de la clave (2048 o 4096 bits)."),
    ("genseckey", cmd_genseckey, "Genera una clave secreta",
     "Pide la contraseña del almacén, el alias, la contraseña del alias\n"
     "y el tamaño de la clave AES (128 o 256 bits)."),
    ("gencert", cmd_gencert, "Genera un certificado a partir de una solicitud de certificado",
     "Pide el alias que firma (el emisor), su contraseña y el archivo .csr.\n"
     "Crea el archivo <nombre>_firmado.crt, válido durante un año."),
    ("importcert", cmd_importcert, "Importa un certificado o una cadena de certificados",
     "Pide el archivo .crt, la contraseña del almacén y un alias nuevo.\n"
     "Enseña el certificado y pregunta si se confía en él."),
    ("importpass", cmd_importpass, "Importa una contraseña",
     "Pide la contraseña del almacén, el alias, la contraseña que se quiere\n"
     "guardar (2 veces) y la contraseña del alias."),
    ("importkeystore", cmd_importkeystore, "Importa una o todas las entradas desde otro almacén de claves",
     "Pide el archivo y la contraseña del almacén de origen, y la contraseña\n"
     "de este almacén. Copia las entradas cuyo alias no exista ya."),
    ("keypasswd", cmd_keypasswd, "Cambia la contraseña de clave de una entrada",
     "Pide la contraseña del almacén, el alias, la contraseña actual del alias\n"
     "y la nueva (2 veces)."),
    ("list", cmd_list, "Enumera las entradas de un almacén de claves",
     "Pide la contraseña del almacén y muestra cada alias con su tipo\n"
     "y su huella SHA-256."),
    ("printcert", cmd_printcert, "Imprime el contenido de un certificado",
     "Pide el archivo .crt (PEM o DER). No necesita el almacén."),
    ("printcertreq", cmd_printcertreq, "Imprime el contenido de una solicitud de certificado",
     "Pide el archivo .csr y comprueba su firma. No necesita el almacén."),
    ("printcrl", cmd_printcrl, "Imprime el contenido de una lista de revocación de certificados",
     "Pide el archivo .crl (PEM o DER). No necesita el almacén."),
    ("storepasswd", cmd_storepasswd, "Cambia la contraseña de almacén de un almacén de claves",
     "Pide la contraseña actual del almacén y la nueva (2 veces)."),
    ("showinfo", cmd_showinfo, "Muestra información relacionada con la seguridad",
     "No pide nada: muestra los algoritmos y versiones que usa el programa."),
]

# Nombres antiguos que se siguen aceptando
ALIAS_COMANDOS = {"genkey": "genkeypair", "export": "exportcert"}


def print_help():
    """Ayuda general, con el mismo formato que 'keytool -help'."""
    print("Herramienta de Gestión de Claves y Certificados\n")
    print("Comandos:\n")
    for nombre, _, descripcion, _ in COMANDOS:
        print(f" -{nombre:<19}{descripcion}")
    print()
    print('Utilice "python mykeytool.py -?, -h, o --help" para este mensaje de ayuda')
    print('Utilice "python mykeytool.py -nombre_comando --help" para obtener la sintaxis de nombre_comando')


def print_command_help(nombre):
    """Ayuda de un comando concreto: 'python mykeytool.py -genkeypair --help'."""
    for cmd, _, descripcion, sintaxis in COMANDOS:
        if cmd == nombre:
            print(f"python mykeytool.py -{cmd}\n")
            print(f"{descripcion}\n")
            print(sintaxis)


def main():
    # add_help=False: la ayuda la escribimos nosotros, con el formato de keytool
    parser = argparse.ArgumentParser(prog="mykeytool.py", add_help=False)
    parser.add_argument("-?", "-h", "-help", "--help", dest="ayuda", action="store_true")

    # Un argumento por comando: vale con un guion (como en Java) o con dos.
    # Todos van al mismo grupo, así solo se puede usar un comando cada vez.
    grupo = parser.add_mutually_exclusive_group()
    for nombre, *_ in COMANDOS:
        opciones = [f"-{nombre}", f"--{nombre}"]
        opciones += [f"-{viejo}" for viejo, nuevo in ALIAS_COMANDOS.items() if nuevo == nombre]
        opciones += [f"--{viejo}" for viejo, nuevo in ALIAS_COMANDOS.items() if nuevo == nombre]
        grupo.add_argument(*opciones, dest="comando", action="store_const", const=nombre)
    args, desconocidos = parser.parse_known_args()

    if desconocidos:
        print(f"Opción no válida: {' '.join(desconocidos)}\n")
        print_help()
        return
    if args.ayuda and args.comando:      # ej: -genkeypair --help
        print_command_help(args.comando)
        return
    if args.ayuda or not args.comando:   # ej: -help, o sin ningún comando
        print_help()
        return

    acciones = {nombre: funcion for nombre, funcion, *_ in COMANDOS}

    # Si algo sale mal mostramos un mensaje claro en vez de un error de Python
    try:
        acciones[args.comando]()
    except (KeytoolError, ValueError) as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nOperación cancelada.")


if __name__ == "__main__":
    main()