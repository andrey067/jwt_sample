﻿﻿using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using JwtSample.Algoritmos;

namespace JwtSample
{
    /// <summary>
    /// Exemplo prático de criação de um JWT (JSON Web Signature) passo a passo.
    /// Demonstra como o token é construído, assinado e apresentado.
    /// </summary>
    static class JwsExample
    {
        // Seleção do algoritmo de assinatura. Pode ser trocado entre RSA, ECDsa ou HMAC
        // Exemplo alternativo: new(new ECDsaSignature(ECCurve.NamedCurves.nistP384, "ES384"))
        private static readonly Assinaturas Assinatura = new(new RSASignature());

        /// <summary>
        /// Executa a demonstração de criação de um JWT passo a passo.
        /// </summary>
        public static void Run()
        {
            // PASSO 0: Define o header com informações sobre o tipo e algoritmo
            var headerSegment = @"{
    ""typ"":""JWT"", 
    ""alg"":""PS256""
}";
            ShowHeader(headerSegment);

            // Define o payload com as informações (claims) do token
            var payloadRepresentation = new Dictionary<string, object>
            {
                { "claim1", 10 },
                { "claim2", "claim2-value" },
                { "name", "Bruno Brito" },
                { "given_name", "Bruno" },
                { "social", new Dictionary<string, string>()
                    {
                        { "facebook", "brunohbrito" },
                        { "google", "bhdebrito" }
                    }
                },
                { "logins", new[] {"brunohbrito", "bhdebrito", "bruno_hbrito"} },

            };
            // Serializa o payload para JSON formatado
            var payloadSegment = JsonSerializer.Serialize(payloadRepresentation, new JsonSerializerOptions() { WriteIndented = true });

            ShowPayload(payloadSegment);

            // PASSO 1: Converte header e payload para UTF-8
            var headerBytes = Encoding.UTF8.GetBytes(headerSegment);
            var payloadBytes = Encoding.UTF8.GetBytes(payloadSegment);
            ShowBytes(headerBytes, payloadBytes);

            // PASSO 2: Codifica header e payload em Base64Url
            var header = Base64UrlEncoder.Encode(headerBytes);
            var payload = Base64UrlEncoder.Encode(payloadBytes);
            ShowBase64Parts(header, payload);

            // PASSO 3: Prepara a parte a ser assinada (header.payload)
            var signatureSegment = $"{header}.{payload}";
            ShowSignatureParts(header, payload);

            // PASSO 4: Assina o conteúdo com a chave privada
            var signatureBytes = Assinatura.Selected.Sign(signatureSegment);

            // PASSO 5: Codifica a assinatura em Base64Url
            var signature = Base64UrlEncoder.Encode(signatureBytes);
            ShowSignatureFinals(signatureBytes, signature);

            // PASSO 6: Gera o JWS final (header.payload.signature)
            ShowJws(signature, header, payload);

            // Exibe as chaves para validação externa no jwt.io
            ShowJwtIoInfo();
        }

        /// <summary>
        /// Exibe as chaves pública e privada para validação em jwt.io.
        /// </summary>
        private static void ShowJwtIoInfo()
        {
            Console.ResetColor();
            Console.WriteLine();
            Console.WriteLine("#######################      Validando no jwt.io      #######################");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Public Key: ");
            Console.ForegroundColor = ConsoleColor.White;
            // Exibe a chave pública em formato JSON
            Console.WriteLine(Assinatura.Selected.PublicKey());
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Private Key: ");
            Console.ForegroundColor = ConsoleColor.White;
            // Exibe a chave privada em formato JSON (use com cuidado!)
            Console.WriteLine(Assinatura.Selected.PrivateKey());
            Console.ResetColor();
        }

        /// <summary>
        /// Exibe a assinatura em bytes e em Base64Url, junto com detalhes do algoritmo.
        /// </summary>
        private static void ShowSignatureFinals(byte[] signatureBytes, string signature)
        {
            Console.WriteLine();
            Console.WriteLine("#######################      PASSO 4: Assinando      #######################");
            Console.WriteLine();
            Console.ResetColor();
            // Exibe o tipo de criptografia utilizada
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Criptografia: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(Assinatura.Selected.AlgoritmType);

            // Exibe o nome do algoritmo (ex: PS256, ES256, HS256)
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Algoritmo: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(Assinatura.Selected.Algorithm);

            // Exibe detalhes adicionais sobre o algoritmo
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Detalhes Algoritmo: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(Assinatura.Selected.JwaDetails());

            // Exibe a assinatura em formato de array de bytes
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Assinatura: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(PrintByteArray(signatureBytes));

            Console.ResetColor();
            Console.WriteLine();
            Console.WriteLine("#######################      PASSO 5: Transforma assinatura em Base64Url      #######################");
            Console.WriteLine();
            // Exibe a assinatura codificada em Base64Url
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Assinatura: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(signature);
            Console.ResetColor();
        }

        /// <summary>
        /// Exibe o header e payload em formato de bytes (representação numérica).
        /// </summary>
        private static void ShowBytes(byte[] headerBytes, byte[] payloadBytes)
        {
            Console.WriteLine();
            Console.WriteLine("#######################      PASSO 1: Convertendo para UTF-8      #######################");
            Console.WriteLine();
            Console.ResetColor();
            // Exibe o header convertido em bytes
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Header: ");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine(PrintByteArray(headerBytes));
            Console.WriteLine();
            // Exibe o payload convertido em bytes
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Payload: ");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine(PrintByteArray(payloadBytes));
            Console.ResetColor();
        }

        /// <summary>
        /// Exibe o JWT final construído (header.payload.signature).
        /// </summary>
        private static void ShowJws(string signature, string header, string payload)
        {
            Console.ResetColor();
            Console.WriteLine();
            Console.WriteLine("#######################      PASSO 6: Criando o JWS      #######################");
            Console.WriteLine();
            // Exibe o formato esperado de um JWT
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Formato JWS: ");
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("<header-base64url>.<payload-base64url>.<assinatura-base64url");
            Console.ResetColor();
            // Exibe o JWT final em cores diferentes para cada parte
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("JWS: ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(header);
            Console.ResetColor();
            Console.Write(".");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(payload);
            Console.ResetColor();
            Console.Write(".");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(signature);
            Console.ResetColor();
        }

        /// <summary>
        /// Exibe o header e payload após codificação em Base64Url.
        /// </summary>
        private static void ShowBase64Parts(string header, string payload)
        {
            Console.WriteLine();
            Console.WriteLine("#######################      PASSO 2: Transforma em Base64Url      #######################");
            Console.WriteLine();
            Console.ResetColor();
            // Exibe o header codificado
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Header: ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(header);
            Console.WriteLine();
            // Exibe o payload codificado
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Payload: ");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(payload);
            Console.ResetColor();
        }

        /// <summary>
        /// Exibe a parte a ser assinada (header.payload em Base64Url).
        /// </summary>
        private static void ShowSignatureParts(string header, string payload)
        {

            Console.WriteLine();
            Console.WriteLine("#######################      PASSO 3: Gera a assinatura      #######################");
            Console.WriteLine();

            Console.ResetColor();
            Console.WriteLine();
            // Exibe o formato da parte a ser assinada
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Formato da Assinatura: ");
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("<header-base64url>.<payload-base64url>");
            // Exibe o conteúdo que será assinado
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("O que sera assinado: ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(header);
            Console.ResetColor();
            Console.Write(".");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(payload);
            Console.ResetColor();
        }

        /// <summary>
        /// Exibe o payload em formato JSON legível.
        /// </summary>
        private static void ShowPayload(string payloadSegment)
        {
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Payload:");
            Console.ForegroundColor = ConsoleColor.Green;
            // Exibe o payload JSON com formatação
            Console.WriteLine(payloadSegment);
            Console.ResetColor();
        }

        /// <summary>
        /// Exibe o header em formato JSON legível.
        /// </summary>
        private static void ShowHeader(string headerSegment)
        {
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Header: ");
            Console.ForegroundColor = ConsoleColor.Green;
            // Exibe o header JSON com formatação
            Console.WriteLine(headerSegment);
            Console.ResetColor();
            Console.WriteLine();
            Console.ResetColor();
        }

        /// <summary>
        /// Converte um array de bytes em uma representação textual legível.
        /// </summary>
        public static string PrintByteArray(byte[] bytes)
        {
            var sb = new StringBuilder("new byte[] { ");
            // Adiciona cada byte na representação de array C#
            foreach (var b in bytes)
            {
                sb.Append(b + ", ");
            }
            sb.Append("}");
            return sb.ToString();
        }
    }
}


