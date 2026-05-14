"""Exemplo prático de criação de um JWT (JSON Web Signature) passo a passo.
Demonstra como o token é construído, assinado e apresentado.
"""
import base64
import json
from assinaturas import Assinaturas
from algoritmos.rsa_signature import RSASignature


def run():
    """Executa a demonstração de criação de um JWT passo a passo."""

    # Seleção do algoritmo de assinatura. Pode ser trocado entre RSA, ECDsa ou HMAC
    # Exemplo alternativo: Assinaturas(ECDsaSignature("P-384", "ES384"))
    assinatura = Assinaturas(RSASignature(algorithm="PS256"))

    # PASSO 0: Define o header com informações sobre o tipo e algoritmo
    header_segment = """{
    "typ": "JWT",
    "alg": "PS256"
}"""
    show_header(header_segment)

    # Define o payload com as informações (claims) do token
    payload_representation = {
        "claim1": 10,
        "claim2": "claim2-value",
        "name": "Bruno Brito",
        "given_name": "Bruno",
        "social": {
            "facebook": "brunohbrito",
            "google": "bhdebrito"
        },
        "logins": ["brunohbrito", "bhdebrito", "bruno_hbrito"]
    }

    # Serializa o payload para JSON formatado
    payload_segment = json.dumps(payload_representation, indent=4)

    show_payload(payload_segment)

    # PASSO 1: Converte header e payload para UTF-8
    header_bytes = header_segment.encode("utf-8")
    payload_bytes = payload_segment.encode("utf-8")
    show_bytes(header_bytes, payload_bytes)

    # PASSO 2: Codifica header e payload em Base64Url
    header = base64_url_encode(header_bytes)
    payload = base64_url_encode(payload_bytes)
    show_base64_parts(header, payload)

    # PASSO 3: Prepara a parte a ser assinada (header.payload)
    signature_segment = f"{header}.{payload}"
    show_signature_parts(header, payload)

    # PASSO 4: Assina o conteúdo com a chave privada
    signature_bytes = assinatura.selected.sign(signature_segment)

    # PASSO 5: Codifica a assinatura em Base64Url
    signature = base64_url_encode(signature_bytes)
    show_signature_finals(signature_bytes, signature, assinatura.selected)

    # PASSO 6: Gera o JWS final (header.payload.signature)
    show_jws(signature, header, payload)

    # Exibe as chaves para validação externa no jwt.io
    show_jwt_io_info(assinatura.selected)


def base64_url_encode(data: bytes) -> str:
    """Codifica bytes para Base64Url (sem padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def show_jwt_io_info(assinatura):
    """Exibe as chaves pública e privada para validação em jwt.io."""
    reset_color()
    print()
    print("#######################      Validando no jwt.io      #######################")
    print()
    print_colored("Public Key: ", "yellow")
    print_colored(assinatura.public_key(), "white")
    print_colored("Private Key: ", "yellow")
    print_colored(assinatura.private_key(), "white")
    reset_color()


def show_signature_finals(signature_bytes, signature, assinatura):
    """Exibe a assinatura em bytes e em Base64Url, junto com detalhes do algoritmo."""
    print()
    print("#######################      PASSO 4: Assinando      #######################")
    print()
    reset_color()

    # Exibe o tipo de criptografia utilizada
    print_colored("Criptografia: ", "yellow")
    print_colored(assinatura.algorithm_type, "cyan")

    # Exibe o nome do algoritmo (ex: PS256, ES256, HS256)
    print_colored("Algoritmo: ", "yellow")
    print_colored(assinatura.algorithm, "cyan")

    # Exibe detalhes adicionais sobre o algoritmo
    print_colored("Detalhes Algoritmo: ", "yellow")
    print_colored(assinatura.jwa_details(), "cyan")

    # Exibe a assinatura em formato de array de bytes
    print_colored("Assinatura: ", "yellow")
    print_colored(print_byte_array(signature_bytes), "cyan")

    reset_color()
    print()
    print("#######################      PASSO 5: Transforma assinatura em Base64Url      #######################")
    print()
    # Exibe a assinatura codificada em Base64Url
    print_colored("Assinatura: ", "yellow")
    print_colored(signature, "cyan")
    reset_color()


def show_bytes(header_bytes, payload_bytes):
    """Exibe o header e payload em formato de bytes (representação numérica)."""
    print()
    print("#######################      PASSO 1: Convertendo para UTF-8      #######################")
    print()
    reset_color()

    # Exibe o header convertido em bytes
    print_colored("Header: ", "yellow")
    print_colored(print_byte_array(header_bytes), "dark_green")
    print()
    # Exibe o payload convertido em bytes
    print_colored("Payload: ", "yellow")
    print_colored(print_byte_array(payload_bytes), "dark_green")
    reset_color()


def show_jws(signature, header, payload):
    """Exibe o JWT final construído (header.payload.signature)."""
    reset_color()
    print()
    print("#######################      PASSO 6: Criando o JWS      #######################")
    print()

    # Exibe o formato esperado de um JWT
    print_colored("Formato JWS: ", "yellow")
    print_colored("<header-base64url>.<payload-base64url>.<assinatura-base64url>", "dark_red")

    reset_color()

    # Exibe o JWT final em cores diferentes para cada parte
    print_colored("JWS: ", "yellow")
    print_colored(header, "red")
    reset_color()
    print(".", end="")
    print_colored(payload, "magenta")
    reset_color()
    print(".", end="")
    print_colored(signature, "cyan")
    print()
    reset_color()


def show_base64_parts(header, payload):
    """Exibe o header e payload após codificação em Base64Url."""
    print()
    print("#######################      PASSO 2: Transforma em Base64Url      #######################")
    print()
    reset_color()

    # Exibe o header codificado
    print_colored("Header: ", "yellow")
    print_colored(header, "red")
    print()
    # Exibe o payload codificado
    print_colored("Payload: ", "yellow")
    print_colored(payload, "magenta")
    reset_color()


def show_signature_parts(header, payload):
    """Exibe a parte a ser assinada (header.payload em Base64Url)."""
    print()
    print("#######################      PASSO 3: Gera a assinatura      #######################")
    print()

    reset_color()
    print()

    # Exibe o formato da parte a ser assinada
    print_colored("Formato da Assinatura: ", "yellow")
    print_colored("<header-base64url>.<payload-base64url>", "dark_red")

    # Exibe o conteúdo que será assinado
    print_colored("O que sera assinado: ", "yellow")
    print_colored(header, "red")
    reset_color()
    print(".", end="")
    print_colored(payload, "magenta")
    print()
    reset_color()


def show_payload(payload_segment):
    """Exibe o payload em formato JSON legível."""
    reset_color()
    print_colored("Payload:", "yellow")
    print_colored(payload_segment, "green")
    reset_color()


def show_header(header_segment):
    """Exibe o header em formato JSON legível."""
    reset_color()
    print_colored("Header: ", "yellow")
    print_colored(header_segment, "green")
    print()
    reset_color()


def print_byte_array(bytes_data: bytes) -> str:
    """Converte um array de bytes em uma representação textual legível."""
    return "bytearray([" + ", ".join(str(b) for b in bytes_data) + "])"


def print_colored(text, color):
    """Imprime texto colorido no terminal."""
    colors = {
        "black": "\033[30m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "magenta": "\033[35m",
        "cyan": "\033[36m",
        "white": "\033[37m",
        "dark_red": "\033[31m",
        "dark_green": "\033[32m",
        "dark_yellow": "\033[33m",
        "reset": "\033[0m",
    }

    color_code = colors.get(color, colors["reset"])
    reset_code = colors["reset"]
    print(f"{color_code}{text}{reset_code}", end="")


def reset_color():
    """Reseta a cor do terminal."""
    print_colored("", "reset")


if __name__ == "__main__":
    run()