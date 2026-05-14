"""Interface que define o contrato para implementações de assinatura criptográfica.
Todas as classes de assinatura (HMAC, RSA, ECDsa) devem implementar esta interface.
"""
from abc import ABC, abstractmethod
from typing import Any


class IJsonWebKey(ABC):
    """Interface que define o contrato para implementações de assinatura criptográfica."""

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """Nome do algoritmo de assinatura (ex: PS256, ES256, HS256).
        Corresponde ao campo 'alg' no header do JWT."""
        pass

    @property
    @abstractmethod
    def algorithm_type(self) -> str:
        """Tipo de algoritmo criptográfico (ex: RSA, ECDsa, HMAC).
        Classifica o tipo de criptografia utilizada."""
        pass

    @abstractmethod
    def sign(self, content: str) -> bytes:
        """Assina o conteúdo fornecido usando a chave privada/segredo do algoritmo.

        Args:
            content: Conteúdo a ser assinado (normalmente header.payload em Base64Url)

        Returns:
            Array de bytes contendo a assinatura criptográfica
        """
        pass

    @abstractmethod
    def public_key(self) -> str:
        """Retorna a chave pública em formato JSON legível.

        Para algoritmos assimétricos (RSA, ECDsa), contém apenas dados públicos.
        Para HMAC, não contém o segredo compartilhado.

        Returns:
            String JSON contendo a chave pública formatada
        """
        pass

    @abstractmethod
    def private_key(self) -> str:
        """Retorna a chave privada completa em formato JSON legível.

        Contém dados sensíveis e deve ser mantido seguro.

        Returns:
            String JSON contendo a chave privada/segredo
        """
        pass

    @abstractmethod
    def jwa_details(self) -> str:
        """Retorna detalhes técnicos sobre o algoritmo utilizado.

        Para ECDsa: informações sobre a curva elíptica.
        Para RSA e HMAC: informações sobre o tamanho da chave.

        Returns:
            String descritiva com detalhes do algoritmo
        """
        pass