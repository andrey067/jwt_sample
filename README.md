# JWT Sample Python

Exemplo de implementação de autenticação JWT com FastAPI.

## Instalação

```bash
pip install -r requirements.txt
```

## Uso

```bash
uvicorn main:app --reload
```

## Endpoints

- `POST /auth/login` - Login e obtenção do token JWT
- `POST /auth/register` - Registro de novo usuário
- `GET /protected` - Rota protegida (requer token)
- `GET /health` - Health check