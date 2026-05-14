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
    /// Implementação de assinatura usando ECDsa (Elliptic Curve Digital Signature Algorithm).
    /// Utiliza a biblioteca Microsoft.IdentityModel.Tokens para gerenciar as chaves.
    /// </summary>
    internal class ECDsaSignature : IJsonWebKey
    {
        // Gerador de números aleatórios para criar chaves seguras
        private static RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        // Caminho onde a chave JSON Web Key (JWK) será armazenada em disco
        private string MyJwkLocation() => Path.Combine(Environment.CurrentDirectory, $"mysupersecretecdsa_{Algorithm}.json");
        // Curva elíptica utilizada para gerar as chaves (ex: nistP256, nistP384, nistP521)
        public ECCurve Curve { get; set; }
        // Algoritmo de assinatura (ex: ES256, ES384, ES512)
        public string Algorithm { get; set; }
        // Tipo de algoritmo criptográfico (neste caso, ECDsa)
        public string AlgoritmType { get; set; }

        /// <summary>
        /// Inicializa uma nova instância de ECDsaSignature com valores padrão.
        /// </summary>
        public ECDsaSignature(ECCurve? curve = null, string algorithm = "ES256", string algoritmType = "ECDsa")
        {
            // Define curva P-256 como padrão se nenhuma for fornecida
            Curve = curve ?? ECCurve.NamedCurves.nistP256;
            Algorithm = algorithm;
            AlgoritmType = algoritmType;
        }

        /// <summary>
        /// Cria uma nova chave ECDsa usando a biblioteca Microsoft.IdentityModel.Tokens.
        /// </summary>
        private JsonWebKey CreateJWK()
        {
            // Cria uma chave de segurança ECDsa com ID único
            var key = new ECDsaSecurityKey(ECDsa.Create(Curve))
            {
                KeyId = Guid.NewGuid().ToString()
            };
            // Converte a chave de segurança para formato JSON Web Key (JWK)
            var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
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
        /// Retorna detalhes sobre o algoritmo de curva utilizado.
        /// </summary>
        public string JwaDetails()
        {
            return $@"Curve: {Curve.Oid.Value}
CurveType: {Curve.Oid.FriendlyName}
";
        }

        // ReSharper disable once InconsistentNaming
        /// <summary>
        /// Assina o conteúdo fornecido usando a chave privada ECDsa.
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
        /// Recupera a chave ECDsa do disco ou cria uma nova se não existir.
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

        /// <summary>
        /// Cria um array de bytes aleatórios do tamanho especificado.
        /// </summary>
        byte[] CreateRandomKey(int length)
        {
            byte[] data = new byte[length];
            _rng.GetBytes(data);
            return data;
        }
    }
}

