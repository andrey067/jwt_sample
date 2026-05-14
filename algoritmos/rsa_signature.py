"""Implementação de assinatura usando RSA (Rivest-Shamir-Adleman).
Utiliza a biblioteca cryptography para gerenciar as chaves.
"""
import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.backends import default_backend
from interfaces import IJsonWebKey


class RSASignature(IJsonWebKey):
    """Implementação de assinatura usando RSA (Rivest-Shamir-Adleman).
    Utiliza a biblioteca cryptography para gerenciar as chaves.
    """

    def __init__(self, algorithm: str = "PS256", algorithm_type: str = "RSA", key_size: int = 2048):
        """Inicializa uma nova instância de RSASignature com valores padrão.

        Args:
            algorithm: Algoritmo de assinatura (ex: PS256, RS256)
            algorithm_type: Tipo de algoritmo criptográfico
            key_size: Tamanho da chave em bits (ex: 2048, 4096)
        """
        self._algorithm = algorithm
        self._algorithm_type = algorithm_type
        self._key_size = key_size

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def algorithm_type(self) -> str:
        return self._algorithm_type

    def _jwk_location(self) -> str:
        """Retorna o caminho onde a chave JSON Web Key (JWK) será armazenada."""
        return os.path.join(os.getcwd(), f"mysupersecretrsa_{self._algorithm}.json")

    def _create_jwk(self) -> dict:
        """Cria uma nova chave RSA e salva em disco.

        Returns:
            Dicionário contendo a chave pública RSA em formato JWK
        """
        # Gera par de chaves RSA com o tamanho especificado
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self._key_size,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        # Converte para formato PEM
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        # Cria dicionário no formato JWK simplificado
        jwk = {
            "kty": "RSA",
            "alg": self._algorithm,
            "n": self._base64url_encode(public_key.public_numbers().n),
            "e": self._base64url_encode(public_key.public_numbers().e),
            "d": self._base64url_encode(private_key.private_numbers().d),
            "p": self._base64url_encode(private_key.private_numbers().p),
            "q": self._base64url_encode(private_key.private_numbers().q),
            "dp": self._base64url_encode(private_key.private_numbers().dmp1),
            "dq": self._base64url_encode(private_key.private_numbers().dmq1),
            "qi": self._base64url_encode(private_key.private_numbers().iqmp),
            "kid": os.urandom(16).hex()
        }

        # Salva a chave em disco
        with open(self._jwk_location(), "w") as f:
            json.dump(jwk, f, indent=2)

        # Retorna apenas dados públicos
        return {
            "kty": "RSA",
            "alg": self._algorithm,
            "n": jwk["n"],
            "e": jwk["e"],
            "kid": jwk["kid"]
        }

    def _base64url_encode(self, value: int) -> str:
        """Codifica um valor inteiro para Base64Url."""
        byte_length = (value.bit_length() + 7) // 8
        return self._base64url_encode_bytes(value.to_bytes(byte_length, byteorder="big"))

    def _base64url_encode_bytes(self, data: bytes) -> str:
        """Codifica bytes para Base64Url (sem padding)."""
        import base64
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _get(self) -> dict:
        """Recupera a chave RSA do disco ou cria uma nova se não existir."""
        if os.path.exists(self._jwk_location()):
            with open(self._jwk_location(), "r") as f:
                return json.load(f)
        return self._create_jwk()

    def sign(self, content: str) -> bytes:
        """Assina o conteúdo fornecido usando a chave privada RSA.

        Args:
            content: Conteúdo a ser assinado (normalmente header.payload em Base64Url)

        Returns:
            Array de bytes contendo a assinatura criptográfica
        """
        key_data = self._get()

        # Reconstrói a chave privada a partir dos componentes JWK
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            rsa_private_numbers,
            rsa_public_numbers,
        )

        n = int.from_bytes(self._base64url_decode(key_data["n"]), byteorder="big")
        e = int.from_bytes(self._base64url_decode(key_data["e"]), byteorder="big")
        d = int.from_bytes(self._base64url_decode(key_data["d"]), byteorder="big")
        p = int.from_bytes(self._base64url_decode(key_data["p"]), byteorder="big")
        q = int.from_bytes(self._base64url_decode(key_data["q"]), byteorder="big")

        public_numbers = rsa_public_numbers(n, e)
        private_numbers = rsa_private_numbers(p, q, d, public_numbers)
        private_key = private_numbers.private_key(default_backend())

        # Determina o hash algorithm baseado no algoritmo
        hash_algo = self._get_hash_algorithm()

        # Assina usando PSS com MGF1
        signature = private_key.sign(
            content.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hash_algo),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hash_algo
        )

        return signature

    def _get_hash_algorithm(self):
        """Retorna o algoritmo de hash baseado no algoritmo de assinatura."""
        from cryptography.hazmat.primitives import hashes

        if self._algorithm in ("PS256", "RS256"):
            return hashes.SHA256()
        elif self._algorithm in ("PS384", "RS384"):
            return hashes.SHA384()
        elif self._algorithm in ("PS512", "RS512"):
            return hashes.SHA512()

        return hashes.SHA256()

    def _base64url_decode(self, data: str) -> bytes:
        """Decodifica uma string Base64Url para bytes."""
        import base64

        # Adiciona padding se necessário
        padding_needed = 4 - (len(data) % 4)
        if padding_needed < 4:
            data += "=" * padding_needed

        return base64.urlsafe_b64decode(data)

    def public_key(self) -> str:
        """Retorna a chave pública em formato JSON legível."""
        key_data = self._get()

        public_key = {
            "kty": key_data["kty"],
            "alg": key_data["alg"],
            "n": key_data["n"],
            "e": key_data["e"],
            "kid": key_data["kid"]
        }

        return json.dumps(public_key, indent=2)

    def private_key(self) -> str:
        """Retorna a chave privada completa em formato JSON legível."""
        key_data = self._get()

        private_key = {
            "kty": key_data["kty"],
            "alg": key_data["alg"],
            "n": key_data["n"],
            "e": key_data["e"],
            "d": key_data["d"],
            "p": key_data["p"],
            "q": key_data["q"],
            "dp": key_data["dp"],
            "dq": key_data["dq"],
            "qi": key_data["qi"],
            "kid": key_data["kid"]
        }

        return json.dumps(private_key, indent=2)

    def jwa_details(self) -> str:
        """Retorna detalhes sobre o tamanho da chave utilizado."""
        return f"KeySize: {self._key_size}"