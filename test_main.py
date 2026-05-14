"""Testes para a API JWT Sample."""
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


class TestHealthEndpoints:
    """Testes dos endpoints de saúde."""

    def test_root(self):
        """Testa a rota raiz."""
        response = client.get("/")
        assert response.status_code == 200
        assert "message" in response.json()

    def test_health_check(self):
        """Testa o health check."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


class TestAuthEndpoints:
    """Testes dos endpoints de autenticação."""

    def test_login_success(self):
        """Testa login com credenciais válidas."""
        response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "secret"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_invalid_credentials(self):
        """Testa login com credenciais inválidas."""
        response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "wrongpassword"}
        )
        assert response.status_code == 401

    def test_login_missing_fields(self):
        """Testa login com campos faltando."""
        response = client.post(
            "/auth/login",
            json={"username": "admin"}
        )
        assert response.status_code == 400

    def test_register_success(self):
        """Testa registro denovo usuário."""
        response = client.post(
            "/auth/register",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "newpassword123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "newuser"
        assert data["email"] == "newuser@example.com"

    def test_register_duplicate_username(self):
        """Testa registro com nome de usuário existente."""
        response = client.post(
            "/auth/register",
            json={
                "username": "admin",
                "email": "another@example.com",
                "password": "password123"
            }
        )
        assert response.status_code == 400


class TestProtectedEndpoints:
    """Testes dos endpoints protegidos."""

    def test_protected_without_token(self):
        """Testa acesso sem token."""
        response = client.get("/protected")
        assert response.status_code == 401

    def test_protected_with_valid_token(self):
        """Testa acesso com token válido."""
        # Primeiro faz login
        login_response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "secret"}
        )
        token = login_response.json()["access_token"]

        # Acessa rota protegida
        response = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "admin"

    def test_protected_with_invalid_token(self):
        """Testa acesso com token inválido."""
        response = client.get(
            "/protected",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401