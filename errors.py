"""Excepciones propias del programa.

Cada error tiene su propia clase y un mensaje por defecto. Todas heredan de
KeytoolError, así main() puede capturarlas todas con un solo except y mostrar
un mensaje claro en vez de una traza de Python.
"""


class KeytoolError(Exception):
    """Error base: todos los errores de mykeytool heredan de este."""
    mensaje = "Error en mykeytool."

    def __init__(self, mensaje=None):
        # Si no nos pasan un mensaje concreto, usamos el de la clase
        super().__init__(mensaje or self.mensaje)


class WrongPasswordError(KeytoolError):
    """La contraseña del almacén o la del alias no es correcta."""
    mensaje = "Contraseña incorrecta."


class AliasExistsError(KeytoolError):
    """Se intenta crear un alias que ya está en el almacén."""
    mensaje = "El alias ya existe en el almacén."


class AliasNotFoundError(KeytoolError):
    """Se busca un alias que no está en el almacén."""
    mensaje = "El alias no existe en el almacén."


class KeystoreNotFoundError(KeytoolError):
    """El archivo del almacén no existe."""
    mensaje = "El almacén no existe. Créalo con --genkeypair."


class KeystoreCorruptError(KeytoolError):
    """El archivo del almacén existe pero está dañado."""
    mensaje = "El almacén está dañado."


class InvalidInputError(KeytoolError):
    """El usuario ha escrito un dato no válido (contraseña corta, no coinciden...)."""
    mensaje = "Dato no válido."