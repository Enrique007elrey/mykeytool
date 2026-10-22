# mykeytool

Programa en Python que imita la herramienta keytool de Java. Sirve para crear claves RSA, guardarlas en un almacén protegido con contraseña y generar una solicitud de certificado (CSR).

## Integrantes

- Enrique Rodrigo Flores
- Pol Cañizares

## Instalación

Hace falta Python 3 y la librería cryptography:

```
pip install cryptography
```

## Archivos

- mykeytool.py: el programa principal, lee los comandos y pregunta los datos.
- keystore.py: guarda y abre el almacén (keystore.dat) cifrado con la contraseña.
- crypto_utils.py: crea las claves RSA, las cifra y genera la CSR.
- errors.py: los errores propios del programa.

## Uso

Ver la ayuda:

```
python mykeytool.py --help
```

Crear una clave (pide contraseña, alias y tus datos):

```
python mykeytool.py --genkeypair
```

Generar la CSR de una clave (crea el archivo alias.csr):

```
python mykeytool.py --certreq
```

Exportar el certificado de una clave (crea alias.crt):

```
python mykeytool.py --export
```

Ver las claves guardadas:

```
python mykeytool.py --list
```

Borrar una clave:

```
python mykeytool.py --delete
```

Ejemplo de uso:

```
$ python mykeytool.py --genkeypair
El almacén no existe, se va a crear uno nuevo.
Nueva contraseña del almacén:
Repite la contraseña:
Alias: enrique
Contraseña del alias (Enter = la misma del almacén):
Datos del titular (Enter = None):
  Nombre y apellidos (CN): Enrique Rodrigo
  Unidad organizativa (OU): DAM
  Organización (O): Instituto
  Ciudad (L): Barcelona
  Provincia (ST): Barcelona
  País, 2 letras (C): ES
¿Es correcto CN=Enrique Rodrigo, OU=DAM, O=Instituto, L=Barcelona, ST=Barcelona, C=ES? (s/n): s
Tamaño de la clave RSA en bits (2048 o 4096, Enter = 2048):
Generando clave RSA de 2048 bits...
Clave 'enrique' guardada en keystore.dat.

$ python mykeytool.py --certreq
Contraseña del almacén:
Alias: enrique
Contraseña del alias (Enter = la misma del almacén):
CSR guardada en enrique.csr.
```

## Funcionamiento

- Si un dato del titular se deja vacío (Enter), se guarda como None. Al final se enseña un resumen para revisarlo; si se contesta "n", se vuelven a pedir.
- La contraseña del alias se pide antes que los datos del titular. Si se pulsa Enter, se usa la del almacén.
- Se puede elegir una clave RSA de 2048 o 4096 bits.
- Hay 3 intentos para escribir bien cada contraseña.
- --list muestra cada alias con su titular, sus bits y la huella SHA-256 de su clave pública.
- errors.py define un error propio para cada caso (contraseña incorrecta, alias repetido o inexistente, almacén inexistente o dañado, dato no válido).

## Pruebas realizadas

- Ver la ayuda con --help: OK
- Crear el almacén y una clave con --genkeypair: OK
- Generar la CSR con --certreq: OK
- Contraseña del almacén incorrecta: muestra error: OK
- Contraseña del alias incorrecta: muestra error: OK
- Crear un alias que ya existe: muestra error: OK
- Usar un alias que no existe: muestra error: OK
- Almacén que no existe o está dañado: muestra error: OK
- País con más de 2 letras o nombre vacío: muestra error: OK
- Listar y borrar claves con --list y --delete: OK
- Exportar el certificado de un alias con --export: OK
- Dejar todos los datos del titular vacíos: se guardan como None: OK
- Contestar "n" en la revisión de los datos: se vuelven a pedir: OK
- Elegir clave de 4096 bits (y rechazar 1024): OK
- Fallar la contraseña 3 veces: acceso bloqueado; fallar 2 y acertar la 3ª: entra: OK
- --list muestra la huella SHA-256 de cada alias: OK