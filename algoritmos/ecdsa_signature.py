"""Implementação de assinatura usando ECDsa (Elliptic Curve Digital Signature Algorithm).
Utiliza a biblioteca cryptography para gerenciar as chaves.
"""
import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from interfaces import IJsonWebKey


class ECDsaSignature(IJsonWebKey):
    """Implementação de assinatura usando ECDsa (Elliptic Curve Digital Signature Algorithm).
    Utiliza a biblioteca cryptography para gerenciar as chaves.
    """

    # Mapeamento de curvas para algoritmos
    CURVES = {
        "P-256": (ec.SECP256R1(), "ES256"),
        "P-384": (ec.SECP384R1(), "ES384"),
        "P-521": (ec.SECP521R1(), "ES512"),
    }

    def __init__(self, curve: str = "P-256", algorithm: str = None, algorithm_type: str = "ECDsa"):
        """Inicializa uma nova instância de ECDsaSignature com valores padrão.

        Args:
            curve: Curva elíptica (P-256, P-384, P-521)
            algorithm: Algoritmo de assinatura (ex: ES256, ES384, ES512)
            algorithm_type: Tipo de algoritmo criptográfico
        """
        self._curve_name = curve
        self._curve, default_alg = self.CURVES.get(curve, (ec.SECP256R1(), "ES256"))
        self._algorithm = algorithm or default_alg
        self._algorithm_type = algorithm_type

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def algorithm_type(self) -> str:
        return self._algorithm_type

    def _jwk_location(self) -> str:
        """Retorna o caminho onde a chave JSON Web Key (JWK) será armazenada."""
        return os.path.join(os.getcwd(), f"mysupersecretecdsa_{self._algorithm}.json")

    def _create_jwk(self) -> dict:
        """Cria uma nova chave ECDsa e salva em disco.

        Returns:
            Dicionário contendo a chave pública ECDsa em formato JWK
        """
        # Gera par de chaves ECDsa
        private_key = ec.generate_private_key(self._curve, default_backend())
        public_key = private_key.public_key()

        # Extrai coordenadas
        public_numbers = public_key.public_numbers()
        private_numbers = private_key.private_numbers()

        # Codifica para Base64Url
        def int_to_base64url(value: int) -> str:
            byte_length = (value.bit_length() + 7) // 8
            return self._base64url_encode_bytes(value.to_bytes(byte_length, byteorder="big"))

        # Cria dicionário no formato JWK
        jwk = {
            "kty": "EC",
            "crv": self._curve_name,
            "alg": self._algorithm,
            "x": int_to_base64url(public_numbers.x),
            "y": int_to_base64url(public_numbers.y),
            "d": int_to_base64url(private_numbers.private_value),
            "kid": os.urandom(16).hex()
        }

        # Salva a chave em disco
        with open(self._jwk_location(), "w") as f:
            json.dump(jwk, f, indent=2)

        # Retorna apenas dados públicos
        return {
            "kty": "EC",
            "crv": self._curve_name,
            "alg": self._algorithm,
            "x": jwk["x"],
            "y": jwk["y"],
            "kid": jwk["kid"]
        }

    def _base64url_encode_bytes(self, data: bytes) -> str:
        """Codifica bytes para Base64Url (sem padding)."""
        import base64
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _get(self) -> dict:
        """Recupera a chave ECDsa do disco ou cria uma nova se não existir."""
        if os.path.exists(self._jwk_location()):
            with open(self._jwk_location(), "r") as f:
                return json.load(f)
        return self._create_jwk()

    def sign(self, content: str) -> bytes:
        """Assina o conteúdo fornecido usando a chave privada ECDsa.

        Args:
            content: Conteúdo a ser assinado (normalmente header.payload em Base64Url)

        Returns:
            Array de bytes contendo a assinatura criptográfica
        """
        key_data = self._get()

        # Reconstrói a chave privada a partir dos componentes JWK
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePrivateKey,
            EllipticCurvePrivateNumbers,
            EllipticCurvePublicNumbers,
        )

        x = int.from_bytes(self._base64url_decode(key_data["x"]), byteorder="big")
        y = int.from_bytes(self._base64url_decode(key_data["y"]), byteorder="big")
        d = int.from_bytes(self._base64url_decode(key_data["d"]), byteorder="big")

        public_numbers = EllipticCurvePublicNumbers(x, y, self._curve)
        private_numbers = EllipticCurvePrivateNumbers(d, public_numbers)
        private_key = private_numbers.private_key(default_backend())

        # Determina o hash algorithm baseado no algoritmo
        hash_algo = self._get_hash_algorithm()

        # Assina usando ECDSA
        signature = private_key.sign(
            content.encode("utf-8"),
            ec.ECDSA(hash_algo)
        )

        return signature

    def _get_hash_algorithm(self):
        """Retorna o algoritmo de hash baseado no algoritmo de assinatura."""
        if self._algorithm == "ES256":
            return hashes.SHA256()
        elif self._algorithm == "ES384":
            return hashes.SHA384()
        elif self._algorithm == "ES512":
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
            "crv": key_data["crv"],
            "alg": key_data["alg"],
            "x": key_data["x"],
            "y": key_data["y"],
            "kid": key_data["kid"]
        }

        return json.dumps(public_key, indent=2)

    def private_key(self) -> str:
        """Retorna a chave privada completa em formato JSON legível."""
        key_data = self._get()

        private_key = {
            "kty": key_data["kty"],
            "crv": key_data["crv"],
            "alg": key_data["alg"],
            "x": key_data["x"],
            "y": key_data["y"],
            "d": key_data["d"],
            "kid": key_data["kid"]
        }

        return json.dumps(private_key, indent=2)

    def jwa_details(self) -> str:
        """Retorna detalhes sobre o algoritmo de curva utilizado."""
        return f"Curve: {self._curve.name}\nCurveType: {self._curve_name}"