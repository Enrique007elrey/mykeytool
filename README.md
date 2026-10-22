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
Datos del titular:
  Nombre y apellidos (CN): Enrique Rodrigo
  Unidad organizativa (OU): DAM
  Organización (O): Instituto
  Ciudad (L): Barcelona
  Provincia (ST): Barcelona
  País, 2 letras (C): ES
Contraseña del alias (Enter = la misma del almacén):
Generando clave RSA de 2048 bits...
Clave 'enrique' guardada en keystore.dat.

$ python mykeytool.py --certreq
Contraseña del almacén:
Alias: enrique
Contraseña del alias (Enter = la misma del almacén):
CSR guardada en enrique.csr.
```

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