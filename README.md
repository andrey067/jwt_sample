# JWT - Demonstração Prática em Python

## Pré-requisitos

* Python 3.8+
* Dependências listadas em `requirements.txt`

## Instalação

```bash
pip install -r requirements.txt
```

## O que é JWT?

JWT (JSON Web Token) é um padrão aberto (RFC 7519) para criar tokens de acesso seguros e autossuficientes. Um JWT é composto por três partes principais separadas por pontos (`.`):

### 1. **Header (Cabeçalho)**
Contém informações sobre o tipo de token e o algoritmo de assinatura utilizado.

```json
{
  "typ": "JWT",
  "alg": "PS256"
}
```

### 2. **Payload (Carga Útil)**
Contém as informações (claims) que você deseja transmitir, como dados do usuário e permissões.

```json
{
  "claim1": 10,
  "claim2": "claim2-value",
  "name": "Bruno Brito",
  "given_name": "Bruno"
}
```

### 3. **Signature (Assinatura)**
É a parte criptográfica que garante a integridade e autenticidade do token.

## Como o JWT Funciona
### Processo de Criação (JWS - JSON Web Signature)

1. **Codificação do Header**: O header é codificado em Base64Url
2. **Codificação do Payload**: O payload é codificado em Base64Url
3. **Criação da Assinatura**: Os dois componentes acima são unidos por um ponto e assinados usando uma chave privada
4. **Resultado**: `header.payload.signature` - um token autossuficiente

### Processo de Validação

Quando um servidor recebe um JWT, ele:

1. Separa o token nas três partes (header, payload e signature)
2. Decodifica o header e payload para ler as informações
3. Recria a assinatura usando a mesma chave privada
4. Compara a assinatura recriada com a assinatura do token
5. Se forem idênticas, o token é válido e não foi modificado

## Algoritmos de Assinatura Disponíveis

Este projeto demonstra a implementação de três algoritmos de assinatura:

### **HMAC (HMACSHA256)**
- Usa um segredo compartilhado (chave simétrica)
- Mais rápido, mas ambas as partes precisam conhecer o segredo
- Ideal para comunicação entre sistemas confiáveis

### **ECDsa (Elliptic Curve Digital Signature Algorithm)**
- Usa criptografia de curva elíptica
- Par de chaves pública/privada (assimétrica)
- Mais eficiente que RSA com mesmo nível de segurança
- Suporte a diferentes curvas: P-256, P-384, P-521

### **RSA (Rivest-Shamir-Adleman)**
- Usa fatoração de números grandes
- Par de chaves pública/privada (assimétrica)
- Amplamente utilizado e bem estabelecido
- Tamanhos de chave: 2048 bits, 4096 bits

## Fluxo do Projeto

1. Define o header (tipo e algoritmo)
2. Define o payload (dados do token)
3. Codifica ambos em Base64Url
4. Assina com a chave privada
5. Codifica a assinatura em Base64Url
6. Gera o token final: `header.payload.signature`

## Como Executar

```bash
python main.py
```

O programa exibe:
- Header codificado
- Payload codificado
- Processo de assinatura
- Token JWT final
- Chaves públicas e privadas para validação em jwt.io

## Algoritmo Padrão

Por padrão, o projeto usa **RSA com PS256**, mas você pode alternar para:
- ECDsa com ES256
- HMAC com HS256

Confira o arquivo `main.py` para ver como mudar o algoritmo.

## Estrutura do Projeto

```
.
├── main.py                 # Programa principal (executa JWS e JWE)
├── assinaturas.py          # Classe para selecionar algoritmo de assinatura
├── interfaces.py           # Interface IJsonWebKey
├── algoritmos/
│   ├── rsa_signature.py    # Implementação RSA
│   ├── ecdsa_signature.py  # Implementação ECDsa
│   └── hmac_signature.py   # Implementação HMAC
├── exemplos/
│   ├── jws_example.py      # Exemplo de criação de JWT (JWS)
│   └── jwe_example.py      # Exemplo de criptografia JWT (JWE)
└── README.md               # Esta documentação
```