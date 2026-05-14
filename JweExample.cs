﻿﻿using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using JwtSample.Algoritmos;

namespace JwtSample
{
    /// <summary>
    /// Exemplo de criação de um JWT criptografado (JWE - JSON Web Encryption).
    /// Diferente do JWS, este exemplo não apenas assina, mas também criptografa o token.
    /// </summary>
    class JweExample
    {
        // Usa RSA como algoritmo de assinatura
        private static readonly RSASignature Assinatura = new RSASignature();

    /// <summary>
    /// Executa a demonstração de criação e validação de um JWT criptografado.
    /// </summary>
    public static async void Run()
    {
        // Define as credenciais de criptografia usando a chave pública RSA
        // Algoritmo de criptografia da chave: RsaOAEP
        // Algoritmo de criptografia do conteúdo: AES128 com HMAC SHA256
        var jweKey = new EncryptingCredentials(
            Assinatura.PublicKeyJsonWebKey(), 
            SecurityAlgorithms.RsaOAEP, 
            SecurityAlgorithms.Aes128CbcHmacSha256);

        // Define as informações (claims) a serem incluídas no token criptografado
        var payloadRepresentation = new List<Claim>()
        {
            new( "claim1", "10" ),
            new( "claim2", "claim2-value"),
            new ( "name", "Bruno Brito" ),
            new ( "given_name", "Bruno" ),
            // Claims múltiplos com a mesma chave
            new ("logins", "brunohbrito"),
            new ("logins", "bhdebrito"),
            new ("logins", "bruno_hbrito"),
        };

        // Cria um manipulador de JWT para gerar e validar tokens
        var handler = new JsonWebTokenHandler();
        var now = DateTime.Now;

        // Define os parâmetros do token (issuer, audience, validade, etc)
        var jwt = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Subject = new ClaimsIdentity(payloadRepresentation),
            EncryptingCredentials = jweKey
        };

        // Gera o token criptografado (JWE)
        var jwe = handler.CreateToken(jwt);

        // Exibe o token JWE (será ilegível sem a chave privada)
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("JWE: ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(jwe);
        Console.ResetColor();

        // Valida o token de forma assíncrona usando a chave privada para descriptografia
        var result = await handler.ValidateTokenAsync(jwe,
            new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                RequireSignedTokens = false,
                TokenDecryptionKey = Assinatura.PrivateJsonWebKey()
            });

        // Serializa os claims descriptografados para exibição
        var claims = JsonSerializer.Serialize(result.Claims, new JsonSerializerOptions() { WriteIndented = true });

        // Exibe os claims descriptografados
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("Claims: ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(claims);
        Console.ResetColor();
    }

    }
}


