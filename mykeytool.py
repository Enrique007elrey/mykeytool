"""Simulador de Java keytool en Python - programa principal."""
import argparse
import getpass

import crypto_utils
import keystore
from errors import AliasExistsError, AliasNotFoundError, KeytoolError


def ask_new_password():
    """Pide una contraseña nueva dos veces y comprueba que coinciden."""
    password = getpass.getpass("Nueva contraseña del almacén: ")
    repeat = getpass.getpass("Repite la contraseña: ")
    if password != repeat:
        raise KeytoolError("Las contraseñas no coinciden.")
    if len(password) < 6:
        raise KeytoolError("La contraseña debe tener al menos 6 caracteres.")
    return password


def ask_dn():
    """Pide los datos del titular (Distinguished Name)."""
    print("Datos del titular:")
    return {
        "CN": input("  Nombre y apellidos (CN): "),
        "OU": input("  Unidad organizativa (OU): "),
        "O": input("  Organización (O): "),
        "L": input("  Ciudad (L): "),
        "ST": input("  Provincia (ST): "),
        "C": input("  País, 2 letras (C): "),
    }


def cmd_genkeypair():
    # 1. Abrir el almacén, o crearlo si no existe
    if keystore.exists():
        store_pass = getpass.getpass("Contraseña del almacén: ")
        entries = keystore.load(store_pass)
    else:
        print("El almacén no existe, se va a crear uno nuevo.")
        store_pass = ask_new_password()
        entries = {}

    # 2. Pedir el alias y comprobar que no está repetido
    alias = input("Alias: ").strip().lower()
    if alias in entries:
        raise AliasExistsError(f"El alias '{alias}' ya existe.")

    # 3. Pedir los datos del titular (build_name comprueba que son correctos)
    dn = ask_dn()
    crypto_utils.build_name(dn)

    # 4. Contraseña del alias (si se deja vacía, se usa la del almacén)
    key_pass = getpass.getpass("Contraseña del alias (Enter = la misma del almacén): ")
    if key_pass == "":
        key_pass = store_pass

    # 5. Generar la clave y guardarla cifrada
    print("Generando clave RSA de 2048 bits...")
    private_key = crypto_utils.generate_rsa_keypair()
    entries[alias] = {
        "dn": dn,
        "key": crypto_utils.encrypt_private_key(private_key, key_pass),
    }
    keystore.save(entries, store_pass)
    print(f"Clave '{alias}' guardada en {keystore.KEYSTORE_FILE}.")


def cmd_certreq():
    # 1. Abrir el almacén y buscar el alias
    store_pass = getpass.getpass("Contraseña del almacén: ")
    entries = keystore.load(store_pass)
    alias = input("Alias: ").strip().lower()
    if alias not in entries:
        raise AliasNotFoundError(f"El alias '{alias}' no existe.")

    # 2. Descifrar la clave privada con la contraseña del alias
    key_pass = getpass.getpass("Contraseña del alias (Enter = la misma del almacén): ")
    if key_pass == "":
        key_pass = store_pass
    private_key = crypto_utils.decrypt_private_key(entries[alias]["key"], key_pass)

    # 3. Crear la CSR y guardarla en un archivo .csr
    name = crypto_utils.build_name(entries[alias]["dn"])
    csr = crypto_utils.create_csr(private_key, name)
    filename = f"{alias}.csr"
    with open(filename, "wb") as f:
        f.write(csr)
    print(f"CSR guardada en {filename}.")


# ---------- Ampliaciones ----------

def cmd_list():
    """Muestra los alias que hay en el almacén."""
    entries = keystore.load(getpass.getpass("Contraseña del almacén: "))
    print(f"El almacén tiene {len(entries)} clave(s):")
    for alias, entry in entries.items():
        print(f"  - {alias}  (titular: {entry['dn']['CN']})")


def cmd_delete():
    """Borra un alias del almacén."""
    store_pass = getpass.getpass("Contraseña del almacén: ")
    entries = keystore.load(store_pass)
    alias = input("Alias a borrar: ").strip().lower()
    if alias not in entries:
        raise AliasNotFoundError(f"El alias '{alias}' no existe.")
    del entries[alias]
    keystore.save(entries, store_pass)
    print(f"Alias '{alias}' borrado.")


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
    except (KeytoolError, ValueError) as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nOperación cancelada.")


if __name__ == "__main__":
    main()