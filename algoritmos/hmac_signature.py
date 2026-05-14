"""Implementação de assinatura usando HMAC (Hash-based Message Authentication Code).
Utiliza um segredo compartilhado para assinar e validar o conteúdo.
"""
import os
import json
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from interfaces import IJsonWebKey


class HmacSignature(IJsonWebKey):
    """Implementação de assinatura usando HMAC (Hash-based Message Authentication Code).
    Utiliza um segredo compartilhado para assinar e validar o conteúdo.
    """

    def __init__(self, key_size: int = 64, algorithm: str = "HS256", algorithm_type: str = "HMAC"):
        """Inicializa uma nova instância de HmacSignature com tamanho de chave padrão.

        Args:
            key_size: Tamanho da chave em bytes
            algorithm: Algoritmo de assinatura (HMACSHA256)
            algorithm_type: Tipo de algoritmo criptográfico (neste caso, HMAC)
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
        return os.path.join(os.getcwd(), f"mysupersecrethmac_{self._key_size}.json")

    def _create_jwk(self) -> dict:
        """Cria uma nova chave HMAC e salva em disco.

        Returns:
            Dicionário contendo a chave HMAC em formato JWK
        """
        # Gera chave secreta aleatória
        key_bytes = secrets.token_bytes(self._key_size)

        # Codifica para Base64Url
        import base64
        k = base64.urlsafe_b64encode(key_bytes).rstrip(b"=").decode("ascii")

        # Cria dicionário no formato JWK
        jwk = {
            "kty": "oct",
            "alg": self._algorithm,
            "k": k,
            "kid": os.urandom(16).hex()
        }

        # Salva a chave em disco
        with open(self._jwk_location(), "w") as f:
            json.dump(jwk, f, indent=2)

        return jwk

    def _get(self) -> dict:
        """Recupera a chave HMAC do disco ou cria uma nova se não existir."""
        if os.path.exists(self._jwk_location()):
            with open(self._jwk_location(), "r") as f:
                return json.load(f)
        return self._create_jwk()

    def sign(self, content: str) -> bytes:
        """Assina o conteúdo fornecido usando a chave HMAC.

        Args:
            content: Conteúdo a ser assinado (normalmente header.payload em Base64Url)

        Returns:
            Array de bytes contendo a assinatura criptográfica
        """
        key_data = self._get()

        # Decodifica a chave Base64Url
        import base64
        k = key_data["k"]
        padding_needed = 4 - (len(k) % 4)
        if padding_needed < 4:
            k += "=" * padding_needed
        key_bytes = base64.urlsafe_b64decode(k)

        # Cria HMAC com a chave
        hmac = HMAC(key_bytes, self._get_hash_algorithm(), backend=default_backend())
        hmac.update(content.encode("utf-8"))

        return hmac.finalize()

    def _get_hash_algorithm(self):
        """Retorna o algoritmo de hash baseado no algoritmo de assinatura."""
        if self._algorithm == "HS256":
            return hashes.SHA256()
        elif self._algorithm == "HS384":
            return hashes.SHA384()
        elif self._algorithm == "HS512":
            return hashes.SHA512()

        return hashes.SHA256()

    def public_key(self) -> str:
        """Retorna a chave pública em formato JSON legível.

        Para HMAC, a "chave pública" é apenas metadados sem o segredo.
        """
        key_data = self._get()

        public_key = {
            "kty": key_data["kty"],
            "alg": key_data["alg"],
            "kid": key_data["kid"]
        }

        return json.dumps(public_key, indent=2)

    def private_key(self) -> str:
        """Retorna a chave privada completa em formato JSON legível.

        Para HMAC, inclui o segredo compartilhado.
        """
        key_data = self._get()

        return json.dumps(key_data, indent=2)

    def jwa_details(self) -> str:
        """Retorna detalhes sobre o tamanho da chave utilizado."""
        return f"KeySize: {self._key_size}"