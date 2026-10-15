from cryptography import x509 #importa el modulo para manejar certificados digitales y solicitudes de certificados
from cryptography.hazmat.primitives import hashes, serialization # importa el modulo para manejar funciones hash y métodos para convertir las claves a formatos legibles
from cryptography.hazmat.primitives.asymmetric import rsa # Importa el algoritmo RSA para crear las claves pública y privada
from cryptography.x509.oid import NameOID # importa el modulo para manejar los identificadores de objetos que son utilizados en los certificados digitales

from errors import WrongPasswordError # Importa un error personalizado que se crea en errors.py


def generate_rsa_keypair(key_size=2048): # Define una funcion para crear las claves RSA
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size) #creamos la clave privada. El 65537 es el numero recomendado por la seguridad para hacer los calculos matematicos rapidos y seguros


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
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    return pem.decode()


def decrypt_private_key(pem, password):
    try:
        return serialization.load_pem_private_key(pem.encode(), password=password.encode())
    except ValueError:
        raise WrongPasswordError("Contraseña del alias incorrecta.")


def create_csr(private_key, name):
    csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)
