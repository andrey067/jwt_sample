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
    /// Implementação de assinatura usando RSA (Rivest-Shamir-Adleman).
    /// Utiliza a biblioteca Microsoft.IdentityModel.Tokens para gerenciar as chaves.
    /// </summary>
    internal class RSASignature : IJsonWebKey
    {
        // Gerador de números aleatórios para criar chaves seguras
        private static RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        // Caminho onde a chave JSON Web Key (JWK) será armazenada em disco
        private string MyJwkLocation() => Path.Combine(Environment.CurrentDirectory, $"mysupersecretrsa_{Algorithm}.json");

        // Algoritmo de assinatura (ex: PS256, RS256)
        public string Algorithm { get; set; }
        // Tipo de algoritmo criptográfico (neste caso, RSA)
        public string AlgoritmType { get; set; }
        // Tamanho da chave em bits (ex: 2048, 4096)
        public int Keysize { get; }

        /// <summary>
        /// Inicializa uma nova instância de RSASignature com valores padrão.
        /// </summary>
        public RSASignature(string algorithm = "PS256", string algoritmType = "RSA", int keysize = 2048)
        {
            Algorithm = algorithm;
            AlgoritmType = algoritmType;
            Keysize = keysize;
        }

        /// <summary>
        /// Cria uma nova chave RSA usando a biblioteca Microsoft.IdentityModel.Tokens.
        /// </summary>
        private JsonWebKey CreateJWK()
        {
            // Cria uma chave de segurança RSA com o tamanho especificado e ID único
            var key = new RsaSecurityKey(RSA.Create(Keysize))
            {
                KeyId = Guid.NewGuid().ToString()
            };
            // Converte a chave de segurança para formato JSON Web Key (JWK)
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
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
        /// Assina o conteúdo fornecido usando a chave privada RSA.
        /// </summary>
        public byte[] Sign(string content)
        {
            // Recupera a chave (cria se não existir)
            var key = Get();
            // Cria um provedor criptográfico da biblioteca Microsoft.IdentityModel
            var cryptoProv = new CryptoProviderFactory();
            // Obtém um provedor de assinatura específico para o algoritmo
            var provider = cryptoProv.CreateForSigning(key, Algorithm);
            // Assina o conteúdo em UTF-8 e retorna a assinatura em bytes
            return provider.Sign(Encoding.UTF8.GetBytes(content));
        }

        /// <summary>
        /// Retorna a chave pública em formato JSON legível.
        /// </summary>
        public string PublicKey()
        {
            // Deserializa a JWK armazenada do arquivo
            var jsonWebKey = JsonSerializer.Deserialize<JsonWebKey>(File.ReadAllText(MyJwkLocation()));
            // Cria um objeto PublicJsonWebKey contendo apenas dados públicos
            // e retorna em JSON formatado de forma legível
            return JsonSerializer.Serialize(new PublicJsonWebKey(jsonWebKey), new JsonSerializerOptions() { WriteIndented = true, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
        }

        /// <summary>
        /// Retorna a chave privada completa em formato JSON legível.
        /// </summary>
        public string PrivateKey()
        {
            // Deserializa a JWK armazenada do arquivo
            var jsonWebKey = JsonSerializer.Deserialize<JsonWebKey>(File.ReadAllText(MyJwkLocation()));
            // Retorna a chave completa (incluindo parte privada) em JSON formatado
            // com nomes de propriedades em camelCase
            return JsonSerializer.Serialize(jsonWebKey, new JsonSerializerOptions() { WriteIndented = true, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull, PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }

        /// <summary>
        /// Retorna a chave pública como objeto JsonWebKey.
        /// </summary>
        public JsonWebKey PublicKeyJsonWebKey()
        {
            // Deserializa a JWK armazenada do arquivo
            var jsonWebKey = JsonSerializer.Deserialize<JsonWebKey>(File.ReadAllText(MyJwkLocation()));
            // Cria um novo JsonWebKey contendo apenas os dados públicos
            return new JsonWebKey(JsonSerializer.Serialize(new PublicJsonWebKey(jsonWebKey), new JsonSerializerOptions() { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull }));
        }

        /// <summary>
        /// Retorna a chave privada completa como objeto JsonWebKey.
        /// </summary>
        public JsonWebKey PrivateJsonWebKey()
        {
            // Deserializa a JWK armazenada do arquivo e retorna o objeto completo
            return JsonSerializer.Deserialize<JsonWebKey>(File.ReadAllText(MyJwkLocation()));
        }

        /// <summary>
        /// Recupera a chave RSA do disco ou cria uma nova se não existir.
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

    }
}

