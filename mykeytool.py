"""Simulador de Java keytool en Python - programa principal."""
import argparse
import getpass
import hashlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

import crypto_utils
import keystore
from errors import (AliasExistsError, AliasNotFoundError, InvalidInputError,
                    KeystoreNotFoundError, KeytoolError, WrongPasswordError)

MAX_INTENTOS = 3                 # intentos para escribir bien una contraseña
TAMANOS_CLAVE = (2048, 4096)     # bits que se pueden elegir para la clave RSA

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

def ask_new_password():
    """Pide una contraseña nueva dos veces y comprueba que coinciden."""
    password = getpass.getpass("Nueva contraseña del almacén: ")
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


def unlock_private_key(entry, store_pass):
    """Pide la contraseña del alias (hasta 3 intentos) y descifra su clave privada."""
    for intento in range(1, MAX_INTENTOS + 1):
        key_pass = getpass.getpass("Contraseña del alias (Enter = la misma del almacén): ")
        if key_pass == "":
            key_pass = store_pass
        try:
            return crypto_utils.decrypt_private_key(entry["key"], key_pass)
        except WrongPasswordError:
            quedan = MAX_INTENTOS - intento
            if quedan == 0:
                raise WrongPasswordError(f"Contraseña del alias incorrecta {MAX_INTENTOS} veces. Acceso bloqueado.")
            print(f"Contraseña incorrecta. Te quedan {quedan} intento(s).")


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
        if respuesta in ("s", "si", "sí", "yes", "y"):
            return dn
        print("Vale, vuelve a escribir los datos.\n")


def ask_key_size():
    """Pregunta el tamaño de la clave RSA: 2048 (por defecto) o 4096 bits."""
    while True:
        texto = input("Tamaño de la clave RSA en bits (2048 o 4096, Enter = 2048): ").strip()
        if texto == "":
            return 2048
        if texto.isdigit() and int(texto) in TAMANOS_CLAVE:
            return int(texto)
        print("Solo se puede elegir 2048 o 4096.")


def sha256_fingerprint(public_key_pem):
    """Huella SHA-256 de la clave pública, en formato AA:BB:CC... como keytool."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    resumen = hashlib.sha256(der).hexdigest().upper()
    return ":".join(resumen[i:i + 2] for i in range(0, len(resumen), 2))


# ---------- Comandos obligatorios ----------

def cmd_genkeypair():
    # 1. Abrir el almacén, o crearlo si no existe
    if keystore.exists():
        entries, store_pass = open_keystore()
    else:
        print("El almacén no existe, se va a crear uno nuevo.")
        store_pass = ask_new_password()
        entries = {}

    # 2. Pedir el alias y comprobar que no está repetido
    alias = input("Alias: ").strip().lower()
    if not alias:
        raise InvalidInputError("El alias no puede estar vacío.")
    if alias in entries:
        raise AliasExistsError(f"El alias '{alias}' ya existe.")

    # 3. Contraseña del alias (antes que los datos, como el keytool real)
    key_pass = ask_alias_password(store_pass)

    # 4. Datos del titular, con revisión al final
    dn = ask_dn()

    # 5. Tamaño de la clave
    key_size = ask_key_size()

    # 6. Generar la clave y guardarla cifrada, junto con la clave pública
    print(f"Generando clave RSA de {key_size} bits...")
    private_key = crypto_utils.generate_rsa_keypair(key_size)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    entries[alias] = {
        "dn": dn,
        "key_size": key_size,
        "key": crypto_utils.encrypt_private_key(private_key, key_pass),
        "public_key": public_pem,
    }
    keystore.save(entries, store_pass)
    print(f"Clave '{alias}' guardada en {keystore.KEYSTORE_FILE}.")


def cmd_certreq():
    # 1. Abrir el almacén y buscar el alias
    entries, store_pass = open_keystore()
    alias = input("Alias: ").strip().lower()
    if alias not in entries:
        raise AliasNotFoundError(f"El alias '{alias}' no existe.")

    # 2. Descifrar la clave privada con la contraseña del alias
    private_key = unlock_private_key(entries[alias], store_pass)

    # 3. Crear la CSR y guardarla en un archivo .csr
    name = crypto_utils.build_name(dn_for_cert(entries[alias]["dn"]))
    csr = crypto_utils.create_csr(private_key, name)
    filename = f"{alias}.csr"
    with open(filename, "wb") as f:
        f.write(csr)
    print(f"CSR guardada en {filename}.")


# ---------- Ampliaciones ----------

def cmd_list():
    """Muestra cada alias del almacén con su titular, sus bits y su huella SHA-256."""
    entries, _ = open_keystore()
    print(f"El almacén tiene {len(entries)} clave(s):\n")
    for alias, entry in entries.items():
        print(f"Alias: {alias}")
        print(f"  Titular: {entry['dn']['CN']}")
        print(f"  Tamaño: RSA de {entry.get('key_size', 2048)} bits")
        if "public_key" in entry:
            print(f"  Huella SHA-256: {sha256_fingerprint(entry['public_key'])}")
        else:
            print("  Huella SHA-256: no disponible (clave creada con una versión anterior)")
        print()


def cmd_delete():
    """Borra un alias del almacén."""
    entries, store_pass = open_keystore()
    alias = input("Alias a borrar: ").strip().lower()
    if alias not in entries:
        raise AliasNotFoundError(f"El alias '{alias}' no existe.")
    del entries[alias]
    keystore.save(entries, store_pass)
    print(f"Alias '{alias}' borrado.")


def cmd_export():
    """Exporta el certificado autofirmado de un alias a un archivo .crt."""
    # 1. Abrir el almacén y buscar el alias
    entries, store_pass = open_keystore()
    alias = input("Alias a exportar: ").strip().lower()
    if alias not in entries:
        raise AliasNotFoundError(f"El alias '{alias}' no existe.")

    # 2. Descifrar la clave privada con la contraseña del alias
    private_key = unlock_private_key(entries[alias], store_pass)

    # 3. Crear un certificado autofirmado válido durante 365 días
    name = crypto_utils.build_name(dn_for_cert(entries[alias]["dn"]))
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # autofirmado: emisor = titular
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    # 4. Guardar el certificado en PEM (sin la clave privada)
    filename = f"{alias}.crt"
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Certificado guardado en {filename}.")


def main():
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description="Simulador en Python de la herramienta keytool de Java.",
    )
    # Hay que elegir uno (y solo uno) de estos comandos
    comandos = parser.add_mutually_exclusive_group(required=True)
    comandos.add_argument("--genkeypair", "--genkey", action="store_true",
                          help="Genera un par de claves RSA y lo guarda en el almacén.")
    comandos.add_argument("--certreq", action="store_true",
                          help="Genera una solicitud de certificado (CSR) en formato PEM.")
    comandos.add_argument("--list", action="store_true",
                          help="Muestra las claves guardadas en el almacén.")
    comandos.add_argument("--delete", action="store_true",
                          help="Borra una clave del almacén.")
    comandos.add_argument("--export", "--exportcert", action="store_true",
                          help="Exporta el certificado de un alias a un archivo .crt.")
    args = parser.parse_args()

    # Si algo sale mal mostramos un mensaje claro en vez de un error de Python
    try:
        if args.genkeypair:
            cmd_genkeypair()
        elif args.certreq:
            cmd_certreq()
        elif args.list:
            cmd_list()
        elif args.delete:
            cmd_delete()
        elif args.export:
            cmd_export()
    except (KeytoolError, ValueError) as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nOperación cancelada.")


if __name__ == "__main__":
    main()