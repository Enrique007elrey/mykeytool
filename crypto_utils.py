from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_rsa_keypair(key_size=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)



DN_FIELDS = {
    "CN": NameOID.COMMON_NAME,               # Nombre y apellidos
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,  # Unidad organizativa
    "O":  NameOID.ORGANIZATION_NAME,         # Organización
    "L":  NameOID.LOCALITY_NAME,             # Ciudad
    "ST": NameOID.STATE_OR_PROVINCE_NAME,    # Provincia
    "C":  NameOID.COUNTRY_NAME,              # País (2 letras)
}


def build_name(fields):
    if not fields.get("CN"):
        raise ValueError("El campo CN (nombre) es obligatorio.")

    pais = fields.get("C", "")
    if pais and (len(pais) != 2 or not pais.isalpha()):
        raise ValueError("El país (C) debe tener 2 letras, por ejemplo ES.")

    atributos = []
    for clave, oid in DN_FIELDS.items():
        valor = fields.get(clave, "").strip()
        if valor:   
            atributos.append(x509.NameAttribute(oid, valor))
    return x509.Name(atributos)


def encrypt_private_key(private_key, password):
    pass


def decrypt_private_key(pem, password):
    pass


def create_self_signed_cert(private_key, name, days=90):
    pass


def create_csr(private_key, name):
    pass
