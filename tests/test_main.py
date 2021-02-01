import re

from fastapi.testclient import TestClient

from src.main import app

client = TestClient(app)


def post_password():
    """
    Post a test password.
    """

    test_password = "test_password123"

    post_response = client.post(
        "/api/new",
        json={
            "password": test_password,
            "views": 1,
            "expiration": 1,
            "email_addresses": "user@example.com",
        },
    )

    return post_response


def get_password(key):
    """
    Get a password from the API
    """

    return client.get(f"/api/{key}")


def test_post_password():
    """
    Create a new password and verify the successful response.
    """

    response = post_password()
    assert response.status_code == 200
    assert re.match(
        r'\{"Success":"Added Password at URL: [a-zA-Z0-9]{32}"\}',
        response.text,
    )


def test_nonexistant_password():
    """
    Invalid keys should return 404
    """

    key = "invalidkey"
    response = get_password(key)

    assert response.status_code == 404


def test_password_removed():

    post_response = post_password()
    post_response = post_response.json()
    key = re.match(
        r"Added Password at URL: ([A-Za-z0-9]{32})", post_response["Success"]
    )[1]

    get_password(key)
    # TODO: Check for the initial result to ensure the password exists prior to deletion.
    get_response = get_password(key)

    assert get_response.status_code == 404