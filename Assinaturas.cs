﻿namespace JwtSample
{
    /// <summary>
    /// Classe responsável por gerenciar a seleção do algoritmo de assinatura.
    /// Implementa o padrão Strategy para permitir trocar entre diferentes algoritmos em tempo de execução.
    /// </summary>
    class Assinaturas
    {
        /// <summary>
        /// Inicializa uma nova instância da classe Assinaturas com um algoritmo específico.
        /// </summary>
        /// <param name="jsonWebKey">Implementação do IJsonWebKey (HMAC, RSA, ECDsa)</param>
        public Assinaturas(IJsonWebKey jsonWebKey)
        {
            // Armazena a implementação do algoritmo de assinatura selecionado
            Selected = jsonWebKey;
        }

        /// <summary>
        /// Propriedade que armazena o algoritmo de assinatura selecionado.
        /// Pode ser trocado em tempo de execução para usar diferentes algoritmos.
        /// </summary>
        public IJsonWebKey Selected { get; set; }

    }
}

