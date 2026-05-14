﻿﻿using Microsoft.IdentityModel.Tokens;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JwtSample.Algoritmos
{
    // ReSharper disable once InconsistentNaming
    /// <summary>
    /// Implementação de assinatura usando HMAC (Hash-based Message Authentication Code).
    /// Utiliza um segredo compartilhado para assinar e validar o conteúdo.
    /// </summary>
    internal class HmacSignature : IJsonWebKey
    {
        // Gerador de números aleatórios para criar chaves seguras
        private static RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        // Caminho onde a chave JSON Web Key (JWK) será armazenada em disco
        private string MyJwkLocation() => Path.Combine(Environment.CurrentDirectory, $"mysupersecrethmac_{Keysize}.json");

        // Algoritmo de assinatura (HMACSHA256)
        public string Algorithm { get; set; }
        // Tipo de algoritmo criptográfico (neste caso, HMAC)
        public string AlgoritmType { get; set; }
        // Tamanho da chave em bytes
        public int Keysize { get; }

        /// <summary>
        /// Inicializa uma nova instância de HmacSignature com tamanho de chave padrão.
        /// </summary>
        public HmacSignature(int keysize = 64)
        {
            Algorithm = "HMACSHA256";
            AlgoritmType = "HMAC";
            Keysize = keysize;
        }

        /// <summary>
        /// Cria uma nova chave HMAC usando a biblioteca Microsoft.IdentityModel.Tokens.
        /// </summary>
        private JsonWebKey CreateJWK()
        {
            // Cria uma chave HMAC com bytes aleatórios do tamanho especificado
            var key = (HMAC)new HMACSHA256(CreateRandomKey(64));
            // Converte a chave criptográfica para formato JSON Web Key (JWK)
            var jwk = JsonWebKeyConverter.ConvertFromSymmetricSecurityKey(new SymmetricSecurityKey(key.Key));
            // Salva a chave em disco
            SaveKey(jwk);
            return jwk;
        }

        /// <summary>
        /// Salva a chave em formato JSON no disco.
        /// </summary>
        private void SaveKey(JsonWebKey key)
        {
            // Serializa a JWK em JSON e escreve no arquivo especificado por MyJwkLocation()
            File.WriteAllText(MyJwkLocation(), JsonSerializer.Serialize(key));
        }

        /// <summary>
        /// Retorna detalhes sobre o tamanho da chave utilizado.
        /// </summary>
        public string JwaDetails()
        {
            return $@"KeySize: {Keysize}";
        }

        // ReSharper disable once InconsistentNaming
        /// <summary>
        /// Assina o conteúdo fornecido usando a chave HMAC.
        /// </summary>
        public byte[] Sign(string content)
        {
            // Recupera a chave (cria se não existir)
            var key = Get();
            // Cria um provedor criptográfico da biblioteca Microsoft.IdentityModel
            var cryptoProv = new CryptoProviderFactory();
            // Obtém um provedor de assinatura específico para HMACSHA256
            var provider = cryptoProv.CreateForSigning(key, Algorithm);
            // Assina o conteúdo em UTF-8 e retorna a assinatura em bytes
            return provider.Sign(Encoding.UTF8.GetBytes(content));
        }

        /// <summary>
        /// Retorna a chave pública em formato JSON legível.
        /// Para HMAC, a "chave pública" é apenas metadados sem o segredo.
        /// </summary>
        public string PublicKey()
        {
            // Deserializa a JWK armazenada do arquivo
            var jsonWebKey = JsonSerializer.Deserialize<JsonWebKey>(File.ReadAllText(MyJwkLocation()));
            // Cria um objeto PublicJsonWebKey contendo apenas dados públicos
            // (sem o valor K que contém o segredo) e retorna em JSON formatado
            return JsonSerializer.Serialize(new PublicJsonWebKey(jsonWebKey), new JsonSerializerOptions() { WriteIndented = true, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
        }

        /// <summary>
        /// Retorna a chave privada completa em formato JSON legível.
        /// Para HMAC, inclui o segredo compartilhado.
        /// </summary>
        public string PrivateKey()
        {
            // Deserializa a JWK armazenada do arquivo
            var jsonWebKey = JsonSerializer.Deserialize<JsonWebKey>(File.ReadAllText(MyJwkLocation()));
            // Retorna a chave completa (incluindo o segredo) em JSON formatado
            // com nomes de propriedades em camelCase
            return JsonSerializer.Serialize(jsonWebKey, new JsonSerializerOptions() { WriteIndented = true, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull, PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }

        /// <summary>
        /// Recupera a chave HMAC do disco ou cria uma nova se não existir.
        /// </summary>
        private JsonWebKey Get()
        {
            // Verifica se a chave já foi salva anteriormente
            if (File.Exists(MyJwkLocation()))
            {
                // Se existir, desserializa e retorna a JWK do arquivo
                return JsonSerializer.Deserialize<JsonWebKey>(File.ReadAllText(MyJwkLocation()));
            }

            // Se não existir, cria uma nova chave
            return CreateJWK();

        }

        /// <summary>Creates a random key byte array.</summary>
        /// <param name="length">The length.</param>
        /// <returns>Array de bytes aleatório do tamanho especificado</returns>
        internal byte[] CreateRandomKey(int length)
        {
            // Cria um array de bytes
            byte[] data = new byte[length];
            // Preenche o array com bytes aleatórios usando um gerador criptograficamente seguro
            _rng.GetBytes(data);
            return data;
        }

    }
}

