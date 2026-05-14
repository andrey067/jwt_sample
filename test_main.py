"""Testes para a API JWT Sample."""
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


class TestHealthEndpoints:
    def test_root(self):
        response = client.get("/")
        assert response.status_code == 200
        assert "message" in response.json()

    def test_health_check(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


class TestAuthEndpoints:
    def test_login_success(self):
        response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "secret"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_invalid_credentials(self):
        response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "wrongpassword"}
        )
        assert response.status_code == 401

    def test_register_success(self):
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


class TestProtectedEndpoints:
    def test_protected_without_token(self):
        response = client.get("/protected")
        assert response.status_code == 401

    def test_protected_with_valid_token(self):
        login_response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "secret"}
        )
        token = login_response.json()["access_token"]

        response = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200