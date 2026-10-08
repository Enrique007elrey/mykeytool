"""Simulador de Java keytool en Python - programa principal."""
import argparse

DEFAULT_KEYSTORE = "keystore.myks"


def cmd_genkeypair(args):
    # De momento solo comprobamos que llega aquí. Lo programaremos después.
    print(f"[genkeypair] almacén={args.keystore} alias={args.alias}")


def cmd_certreq(args):
    print(f"[certreq] almacén={args.keystore} alias={args.alias} archivo={args.file}")


def build_parser():
    """Define qué comandos y opciones entiende el programa."""
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description="Simulador en Python de la herramienta keytool de Java.",
    )

    # Grupo de comandos: hay que elegir UNO y solo uno
    comandos = parser.add_mutually_exclusive_group(required=True)
    comandos.add_argument("--genkeypair", "--genkey", dest="command",
                          action="store_const", const=cmd_genkeypair,
                          help="Genera un par de claves RSA y lo guarda en el almacén.")
    comandos.add_argument("--certreq", dest="command",
                          action="store_const", const=cmd_certreq,
                          help="Genera una solicitud de firma de certificado (CSR) en PEM.")

    # Opciones que acompañan a los comandos
    parser.add_argument("--keystore", default=DEFAULT_KEYSTORE,
                        help=f"Archivo del almacén (por defecto: {DEFAULT_KEYSTORE}).")
    parser.add_argument("--alias", help="Alias de la entrada (si no se indica, se pregunta).")
    parser.add_argument("--file", help="Archivo de salida para la CSR.")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()   # lee lo que se ha escrito en el terminal
    args.command(args)           # ejecuta la función del comando elegido


if __name__ == "__main__":
    main()