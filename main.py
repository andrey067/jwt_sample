"""API de autenticação JWT com FastAPI."""
from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from config import get_settings
from schemas import Token, UserCreate, UserResponse, MessageResponse
from auth import (
    authenticate_user,
    create_access_token,
    get_password_hash,
    get_user,
    get_current_active_user,
    fake_users_db
)

settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    description="API de exemplo para autenticação JWT com FastAPI",
    version="1.0.0"
)


@app.get("/", tags=["Root"])
async def root():
    """Rota raiz."""
    return {"message": "JWT Sample API", "docs": "/docs"}


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "app": settings.app_name}


@app.post("/auth/token", response_model=Token, tags=["Auth"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Endpoint para login e obtenção de token JWT.

    - **username**: Nome de usuário
    - **password**: Senha do usuário
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nome de usuário ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/auth/login", response_model=Token, tags=["Auth"])
async def login(login_data: dict):
    """
    Endpoint alternativo para login (JSON body).

    - **username**: Nome de usuário
    - **password**: Senha do usuário
    """
    username = login_data.get("username")
    password = login_data.get("password")

    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username e password são obrigatórios"
        )

    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nome de usuário ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/auth/register", response_model=UserResponse, tags=["Auth"])
async def register(user_data: UserCreate):
    """
    Endpoint para registro de novo usuário.

    - **username**: Nome de usuário único
    - **email**: Email do usuário (opcional)
    - **password**: Senha do usuário
    """
    # Verifica se usuário já existe
    if get_user(user_data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nome de usuário já existe"
        )

    # Verifica se email já está em uso
    for user in fake_users_db.values():
        if user.get("email") == user_data.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email já está em uso"
            )

    # Cria novo usuário
    new_id = max([u["id"] for u in fake_users_db.values()]) + 1
    new_user = {
        "id": new_id,
        "username": user_data.username,
        "email": user_data.email,
        "hashed_password": get_password_hash(user_data.password),
        "disabled": False
    }

    fake_users_db[user_data.username] = new_user

    return UserResponse(
        id=new_user["id"],
        username=new_user["username"],
        email=new_user["email"],
        disabled=new_user["disabled"]
    )


@app.get("/protected", response_model=UserResponse, tags=["Protected"])
async def protected_route(current_user: dict = Depends(get_current_active_user)):
    """
    Rota protegida - requer token JWT válido.

    Retorna informações do usuário autenticado.
    """
    return UserResponse(
        id=current_user["id"],
        username=current_user["username"],
        email=current_user.get("email"),
        disabled=current_user.get("disabled", False)
    )


@app.get("/protected/data", tags=["Protected"])
async def protected_data(current_user: dict = Depends(get_current_active_user)):
    """
    Rota protegida com dados de exemplo.
    """
    return {
        "message": "Dados protegidos",
        "user": current_user["username"],
        "data": {
            "balance": 1000.00,
            "account_id": current_user["id"],
            "role": "admin" if current_user["username"] == "admin" else "user"
        }
    }


@app.post("/auth/logout", response_model=MessageResponse, tags=["Auth"])
async def logout(current_user: dict = Depends(get_current_active_user)):
    """
    Endpoint de logout (simulado).

    Em uma aplicação real, você adicionaria o token a uma blacklist.
    """
    return {"message": f"Usuário {current_user['username']} deslogado com sucesso"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)