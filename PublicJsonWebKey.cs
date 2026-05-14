using Microsoft.IdentityModel.Tokens;
using System.Text.Json.Serialization;

namespace JwtSample
{
    /// <summary>
    /// Classe que representa apenas a parte pública de uma chave JSON Web Key.
    /// Remove informações sensíveis como chaves privadas e segredos.
    /// Usada para exportar chaves públicas de forma segura.
    /// </summary>
    public class PublicJsonWebKey
    {
        /// <summary>
        /// Inicializa uma nova instância com os dados de uma JsonWebKey, mantendo apenas a parte pública.
        /// </summary>
        public PublicJsonWebKey(JsonWebKey key)
        {
            // Copia os dados públicos da chave original
            Kty = key.Kty;
            Use = key.Use;
            Kid = key.Kid;
            Crv = key.Crv;
            Alg = key.Alg;
            
            // Dados públicos da chave (variam conforme o tipo)
            N = key.N;      // Módulo RSA
            E = key.E;      // Expoente RSA
            X = key.X;      // Coordenada X da curva elíptica
            Y = key.Y;      // Coordenada Y da curva elíptica
        }

        /// <summary>Tipo de chave (kty) - ex: RSA, EC, oct</summary>
        [JsonPropertyName("kty")]
        public string Kty { get; set; }

        /// <summary>Uso da chave (use) - ex: sig (assinatura)</summary>
        [JsonPropertyName("use")]
        public string Use { get; set; }

        /// <summary>ID da chave (kid) - identificador único da chave</summary>
        [JsonPropertyName("kid")]
        public string Kid { get; set; }

        /// <summary>Curva elíptica (crv) - ex: P-256, P-384, P-521</summary>
        [JsonPropertyName("crv")]
        public string Crv { get; set; }

        /// <summary>Algoritmo (alg) - ex: RS256, ES256, HS256</summary>
        [JsonPropertyName("alg")]
        public string Alg { get; set; }

        /// <summary>Módulo RSA (n) - componente público da chave RSA</summary>
        [JsonPropertyName("n")]
        public string N { get; set; }

        /// <summary>Expoente RSA (e) - componente público da chave RSA</summary>
        [JsonPropertyName("e")]
        public string E { get; set; }

        /// <summary>Coordenada X da curva elíptica (x) - componente público da chave EC</summary>
        [JsonPropertyName("x")]
        public string X { get; set; }

        /// <summary>Coordenada Y da curva elíptica (y) - componente público da chave EC</summary>
        [JsonPropertyName("y")]
        public string Y { get; set; }
    }
}

