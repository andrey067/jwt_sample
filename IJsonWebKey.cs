﻿namespace JwtSample
{
    /// <summary>
    /// Interface que define o contrato para implementações de assinatura criptográfica.
    /// Todas as classes de assinatura (HMAC, RSA, ECDsa) devem implementar esta interface.
    /// </summary>
    public interface IJsonWebKey
    {
        /// <summary>
        /// Assina o conteúdo fornecido usando a chave privada/segredo do algoritmo.
        /// </summary>
        /// <param name="content">Conteúdo a ser assinado (normalmente header.payload em Base64Url)</param>
        /// <returns>Array de bytes contendo a assinatura criptográfica</returns>
        byte[] Sign(string content);

        /// <summary>
        /// Retorna a chave pública em formato JSON legível.
        /// Para algoritmos assimétricos (RSA, ECDsa), contém apenas dados públicos.
        /// Para HMAC, não contém o segredo compartilhado.
        /// </summary>
        /// <returns>String JSON contendo a chave pública formatada</returns>
        string PublicKey();

        /// <summary>
        /// Retorna a chave privada completa em formato JSON legível.
        /// Contém dados sensíveis e deve ser mantido seguro.
        /// </summary>
        /// <returns>String JSON contendo a chave privada/segredo</returns>
        string PrivateKey();

        /// <summary>
        /// Retorna detalhes técnicos sobre o algoritmo utilizado.
        /// Para ECDsa: informações sobre a curva elíptica.
        /// Para RSA e HMAC: informações sobre o tamanho da chave.
        /// </summary>
        /// <returns>String descritiva com detalhes do algoritmo</returns>
        string JwaDetails();

        /// <summary>
        /// Nome do algoritmo de assinatura (ex: PS256, ES256, HMACSHA256).
        /// Corresponde ao campo "alg" no header do JWT.
        /// </summary>
        string Algorithm { get; }

        /// <summary>
        /// Tipo de algoritmo criptográfico (ex: RSA, ECDsa, HMAC).
        /// Classifica o tipo de criptografia utilizada.
        /// </summary>
        string AlgoritmType { get; set; }
    }
}
