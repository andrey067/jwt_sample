"""Programa principal - Demonstração de JWT em Python.
Este programa executa exemplos práticos de criação de tokens JWT.
"""
from exemplos.jws_example import run as run_jws

# Exibe a demonstração de um JWT assinado (JWS - JSON Web Signature)
# Este exemplo mostra passo a passo como um JWT é criado, assinado e formatado
print("==================================== JWS EXAMPLE ====================================")
run_jws()
print()

# JWE Example - PLACEHOLDER
# Para implementar a demonstração de JWE (JSON Web Encryption), adicione o código equivalente
# O JWE é usado quando você precisa criptografar o payload, não apenas assiná-lo
# O processo é similar ao JWS, mas adiciona uma camada de criptografia com chave pública
print("==================================== JWE EXAMPLE ====================================")
print()
print("JWE (JSON Web Encryption) - Em desenvolvimento")
print("Para implementar JWE, use a mesma estrutura do JWS mas com criptografia de conteúdo.")
print()

print("==================================== FIM ====================================")