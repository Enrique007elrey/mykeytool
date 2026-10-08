"""Operaciones criptográficas: claves RSA, certificados y CSR."""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_rsa_keypair(key_size=2048):
    """Genera y devuelve una clave privada RSA."""
    # 65537 es el exponente público estándar que usa todo el mundo.
    # La clave pública va dentro de la privada: private_key.public_key()
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


# Campos del Distinguished Name: abreviatura -> identificador oficial (OID)
DN_FIELDS = {
    "CN": NameOID.COMMON_NAME,               # Nombre y apellidos
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,  # Unidad organizativa
    "O":  NameOID.ORGANIZATION_NAME,         # Organización
    "L":  NameOID.LOCALITY_NAME,             # Ciudad
    "ST": NameOID.STATE_OR_PROVINCE_NAME,    # Provincia
    "C":  NameOID.COUNTRY_NAME,              # País (2 letras)
}


def build_name(fields):
    """Recibe {'CN':..., 'OU':..., 'O':..., 'L':..., 'ST':..., 'C':...} y devuelve un x509.Name."""
    if not fields.get("CN"):
        raise ValueError("El campo CN (nombre) es obligatorio.")

    pais = fields.get("C", "")
    if pais and (len(pais) != 2 or not pais.isalpha()):
        raise ValueError("El país (C) debe tener 2 letras, por ejemplo ES.")

    atributos = []
    for clave, oid in DN_FIELDS.items():
        valor = fields.get(clave, "").strip()
        if valor:   # los campos vacíos no se añaden
            atributos.append(x509.NameAttribute(oid, valor))
    return x509.Name(atributos)


def encrypt_private_key(private_key, password):
    """Devuelve la clave privada en PEM cifrada con la contraseña del alias."""
    pass


def decrypt_private_key(pem, password):
    """Devuelve la clave privada. Lanza WrongPasswordError si la contraseña es incorrecta."""
    pass


def create_self_signed_cert(private_key, name, days=90):
    """Devuelve un certificado autofirmado en PEM."""
    pass


def create_csr(private_key, name):
    """Devuelve la CSR en formato PEM (bytes)."""
    pass
