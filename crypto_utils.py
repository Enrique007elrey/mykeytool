"""Operaciones criptográficas: claves RSA, certificados y CSR."""


def generate_rsa_keypair(key_size=2048):
    """Genera y devuelve una clave privada RSA."""
    pass


def build_name(fields):
    """Recibe {'CN':..., 'OU':..., 'O':..., 'L':..., 'ST':..., 'C':...} y devuelve un x509.Name."""
    pass


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