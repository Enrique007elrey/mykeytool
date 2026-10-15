from cryptography import x509 #importa el modulo para manejar certificados digitales y solicitudes de certificados
from cryptography.hazmat.primitives import hashes, serialization # importa el modulo para manejar funciones hash y métodos para convertir las claves a formatos legibles
from cryptography.hazmat.primitives.asymmetric import rsa # Importa el algoritmo RSA para crear las claves pública y privada
from cryptography.x509.oid import NameOID # importa el modulo para manejar los identificadores de objetos que son utilizados en los certificados digitales

from errors import WrongPasswordError # Importa un error personalizado que se crea en errors.py


def generate_rsa_keypair(key_size=2048): # Define una funcion para crear las claves RSA
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size) #creamos la clave privada. El 65537 es el numero recomendado por la seguridad para hacer los calculos matematicos rapidos y seguros


DN_FIELDS = {                                #Es un diccionario que traduce abreviaturas estándar de certificados
    "CN": NameOID.COMMON_NAME,               # Nombre y apellidos
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,  # Unidad organizativa
    "O":  NameOID.ORGANIZATION_NAME,         # Organización
    "L":  NameOID.LOCALITY_NAME,             # Ciudad
    "ST": NameOID.STATE_OR_PROVINCE_NAME,    # Provincia
    "C":  NameOID.COUNTRY_NAME,              # País (2 letras)
}


def build_name(fields):
    if not fields.get("CN"): #Si el usuario no escribe el nombre (CN), el programa lanza un error y para.
        raise ValueError("El campo CN (nombre) es obligatorio.")

    pais = fields.get("C", "") #comprobamos el pais. Si lo ha rellenado, tiene que tener 2 letras exactas y ser solo texto.
    if pais and (len(pais) != 2 or not pais.isalpha()): # el isalpha mira si la cadena no esta vacia y todos sus caracteres son letras
        raise ValueError("El país (C) debe tener 2 letras, por ejemplo ES.")

    atributos = [] #Creamos una lista vacia para guardar los datos.
    for clave, identificador in DN_FIELDS.items(): #Recorremos el diccionario
        valor = fields.get(clave, "").strip() #Quitamos los espacios en blanco al principio y al final de lo que escribio el usuario
        if valor: #Si el usuario a escrito algo, lo añadimos a la lista de atributos.
            atributos.append(x509.NameAttribute(identificador, valor))  #Añade al final de la lista un objeto NameAttribute que contiene el identificador y el valor del campo.
    return x509.Name(atributos) # Empaquetamos el certificados y lo devolvemos


def encrypt_private_key(private_key, password): # Cogemos la clave privada y la convertimos con las siguientes instrucciones
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, # La guardamos en formato PEM
        format=serialization.PrivateFormat.PKCS8, # Usamos el estándar PKCS8 para guardar claves
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()), # Usamos la mejor encriptación disponible para proteger la clave privada con la contraseña que nos ha dado el usuario
    )
    return pem.decode()


def decrypt_private_key(pem, password):
    try: 
        return serialization.load_pem_private_key(pem.encode(), password=password.encode())# Le decimos a la librería que cargue y descifre la llave leyendo el PEM y usando la contraseña.
    except ValueError:
        raise WrongPasswordError("Contraseña del alias incorrecta.")


def create_csr(private_key, name): # Definimos la función. Necesita la private_key y el nombre oficial del titular
    csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(private_key, hashes.SHA256()) # 1. Prepara el "formulario en blanco" 2. Rellena el formulario con los datos del titular 3. Firma el formulario con tu clave privada y le pone seguridad SHA256 para demostrar que es tuyo
    return csr.public_bytes(serialization.Encoding.PEM) # ransforma la peticion que estaba en la memoria de Python en texto
