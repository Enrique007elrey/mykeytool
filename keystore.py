"""Persistencia cifrada del almacén de claves."""


class KeyStore:
    def __init__(self, path):
        self.path = path
        self.entries = {}

    @classmethod
    def load(cls, path, password):
        """Abre y descifra el almacén.
        Errores: KeystoreNotFoundError, WrongPasswordError, KeystoreCorruptError."""
        pass

    def save(self, password):
        """Cifra el almacén y lo guarda en disco."""
        pass

    def has_alias(self, alias):
        pass

    def add_entry(self, alias, key_pem, cert_pem):
        """Lanza AliasExistsError si el alias ya existe."""
        pass

    def get_entry(self, alias):
        """Lanza AliasNotFoundError si no existe."""
        pass