﻿using System;
using JwtSample;

// Exibe a demonstração de um JWT assinado (JWS - JSON Web Signature)
// Este exemplo mostra passo a passo como um JWT é criado, assinado e formatado
Console.WriteLine("==================================== JWS EXAMPLE ====================================");
JwsExample.Run();
Console.WriteLine();

// Exibe a demonstração de um JWT criptografado (JWE - JSON Web Encryption)
// Este exemplo mostra como criptografar e descriptografar um token
Console.WriteLine("==================================== JWE EXAMPLE ====================================");
JweExample.Run();

