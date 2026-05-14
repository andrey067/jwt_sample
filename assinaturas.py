"""Classe responsável por gerenciar a seleção do algoritmo de assinatura.
Implementa o padrão Strategy para permitir trocar entre diferentes algoritmos em tempo de execução.
"""
from interfaces import IJsonWebKey


class Assinaturas:
    """Classe responsável por gerenciar a seleção do algoritmo de assinatura."""

    def __init__(self, json_web_key: IJsonWebKey):
        """Inicializa uma nova instância da classe Assinaturas com um algoritmo específico.

        Args:
            json_web_key: Implementação do IJsonWebKey (HMAC, RSA, ECDsa)
        """
        # Armazena a implementação do algoritmo de assinatura selecionado
        self._selected = json_web_key

    @property
    def selected(self) -> IJsonWebKey:
        """Propriedade que armazena o algoritmo de assinatura selecionado.

        Pode ser trocado em tempo de execução para usar diferentes algoritmos.
        """
        return self._selected

    @selected.setter
    def selected(self, value: IJsonWebKey):
        """Define um novo algoritmo de assinatura."""
        self._selected = value