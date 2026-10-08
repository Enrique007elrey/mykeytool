"""Excepciones propias del programa."""


class KeytoolError(Exception):
    pass


class WrongPasswordError(KeytoolError):
    pass


class AliasExistsError(KeytoolError):
    pass


class AliasNotFoundError(KeytoolError):
    pass


class KeystoreNotFoundError(KeytoolError):
    pass


class KeystoreCorruptError(KeytoolError):
    pass