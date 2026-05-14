"""Modelos Pydantic para a API."""
from pydantic import BaseModel, EmailStr
from typing import Optional


class UserBase(BaseModel):
    """Modelo base para usuário."""
    username: str
    email: Optional[EmailStr] = None


class UserCreate(UserBase):
    """Modelo para criação de usuário."""
    password: str


class UserResponse(UserBase):
    """Modelo de resposta do usuário."""
    id: int
    disabled: Optional[bool] = False

    class Config:
        from_attributes = True


class Token(BaseModel):
    """Modelo do token de acesso."""
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Dados extraídos do token."""
    username: Optional[str] = None


class LoginRequest(BaseModel):
    """Modelo para login."""
    username: str
    password: str


class MessageResponse(BaseModel):
    """Modelo de resposta de mensagem."""
    message: str