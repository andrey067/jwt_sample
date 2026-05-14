﻿﻿using Microsoft.IdentityModel.Tokens;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JwtSample
{    
    /// <summary>
    /// Implementação minimal de assinatura ECDsa sem dependências externas adicionais.
    /// Utiliza apenas os namespaces padrão do .NET para criar chaves e assinar conteúdo.
    /// </summary>
    internal class ECDsaMinimalDepsSignature : IJsonWebKey
    {
        // Gerador de números aleatórios para criar chaves seguras
        private static RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        // Caminho onde a chave JSON Web Key (JWK) será armazenada em disco
        private static readonly string MyJwkLocation = Path.Combine(Environment.CurrentDirectory, $"mysupersecretecdsa.json");

        // Curva elíptica utilizada para gerar as chaves
        public ECCurve Curve { get; set; }
        // Algoritmo de assinatura (ex: ES256, ES384, ES512)
        public string Algorithm { get; set; }
        // Tipo de algoritmo criptográfico (neste caso, ECDsa)
        public string AlgoritmType { get; set; }

        /// <summary>
        /// Inicializa uma nova instância de ECDsaMinimalDepsSignature com valores padrão.
        /// </summary>
        public ECDsaMinimalDepsSignature(ECCurve? curve = null, string algorithm = "ES256", string algoritmType = "ECDsa")
        {
            // Define curva P-256 como padrão se nenhuma for fornecida
            Curve = curve ?? ECCurve.NamedCurves.nistP256;
            Algorithm = algorithm;
            AlgoritmType = algoritmType;
        }

        /// <summary>
        /// Cria uma nova chave ECDsa e a salva em disco em formato JSON Web Key.
        /// </summary>
        private ECDsa CreateJWK()
        {
            // Cria uma nova chave ECDsa com a curva especificada
            var key = ECDsa.Create(Curve);
            SaveKey(key);
            return key;
        }

        /// <summary>
        /// Salva a chave ECDsa em formato JSON Web Key (JWK) no disco.
        /// </summary>
        private void SaveKey(ECDsa key)
        {
            // Exporta os parâmetros da chave privada
            var parameters = key.ExportParameters(true);
            // Cria um ID único para a chave
            var id = CreateUniqueId();
            // Monta a estrutura JWK com os parâmetros da chave
            var jwk = new JsonWebKey()
            {
                Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
                Use = "sig",
                Kid = id,
                KeyId = id,
                X = Base64UrlEncoder.Encode(parameters.Q.X), // Coordenada X da chave pública
                Y = Base64UrlEncoder.Encode(parameters.Q.Y), // Coordenada Y da chave pública
                D = Base64UrlEncoder.Encode(parameters.D),   // Componente privado da chave
                Crv = JsonWebKeyECTypes.P256,
                Alg = Algorithm
            };
            // Serializa e salva a JWK em arquivo JSON
            File.WriteAllText(MyJwkLocation, JsonSerializer.Serialize(jwk));
        }

        /// <summary>
        /// Retorna detalhes sobre o algoritmo de curva utilizado.
        /// </summary>
        public string JwaDetails()
        {
            return $@"Curve: {Curve.Oid.Value}CurveType: {Curve.Oid.FriendlyName}";
        }

        /// <summary>
        /// Assina o conteúdo fornecido usando a chave privada ECDsa.
        /// </summary>
        public byte[] Sign(string content)
        {
            // Recupera a chave (cria se não existir)
            var key = Get();
            // Assina o conteúdo usando SHA256 e retorna a assinatura em bytes
            return key.SignData(Encoding.UTF8.GetBytes(content), HashAlgorithmName.SHA256);
        }

        /// <summary>
        /// Retorna a chave pública em formato JSON legível.
        /// </summary>
        public string PublicKey()
        {
            // Deserializa a JWK armazenada
            var jsonWebKey = JsonSerializer.Deserialize<JsonWebKey>(File.ReadAllText(MyJwkLocation));
            // Retorna apenas a parte pública da chave em JSON formatado
            return JsonSerializer.Serialize(new PublicJsonWebKey(jsonWebKey), new JsonSerializerOptions() { WriteIndented = true, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
        }

        /// <summary>
        /// Retorna a chave privada completa em formato JSON legível.
        /// </summary>
        public string PrivateKey()
        {
            // Deserializa a JWK armazenada
            var jsonWebKey = JsonSerializer.Deserialize<JsonWebKey>(File.ReadAllText(MyJwkLocation));
            // Retorna a chave completa (incluindo parte privada) em JSON formatado
            return JsonSerializer.Serialize(jsonWebKey, new JsonSerializerOptions() { WriteIndented = true, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull, PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }

        /// <summary>
        /// Recupera a chave ECDsa do disco ou cria uma nova se não existir.
        /// </summary>
        private ECDsa Get()
        {
            // Verifica se a chave já foi salva anteriormente
            if (File.Exists(MyJwkLocation))
            {
                // Lê e deserializa a JWK do arquivo
                var jsonWebKey = JsonSerializer.Deserialize<JsonWebKey>(File.ReadAllText(MyJwkLocation));
                // Reconstrói os parâmetros da chave a partir da JWK
                var parameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = Base64UrlEncoder.DecodeBytes(jsonWebKey.D),
                    Q = new ECPoint()
                    {
                        X = Base64UrlEncoder.DecodeBytes(jsonWebKey.X),
                        Y = Base64UrlEncoder.DecodeBytes(jsonWebKey.Y),
                    }
                };
                // Cria e retorna a chave ECDsa
                return ECDsa.Create(parameters);
            }

            // Se não existir, cria uma nova chave
            return CreateJWK();
        }

        /// <summary>
        /// Cria um ID único em Base64Url para identificar a chave.
        /// </summary>
        string CreateUniqueId(int length = 16)
        {
            return Base64UrlEncoder.Encode(CreateRandomKey(length));
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

