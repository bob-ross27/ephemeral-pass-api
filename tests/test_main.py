import re

from fastapi.testclient import TestClient

import src.main as e_api

client = TestClient(e_api.app)


def post_password(views):
    """
    Post a test password.
    """

    test_password = "test_password123"

    post_response = client.post(
        "/api/new",
        json={
            "password": test_password,
            "views": views,
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

    response = post_password(1)
    response_re = re.match(
        r'\{"Success":"Added Password at URL: ([a-zA-Z0-9]{32})"\}',
        response.text,
    )
    assert response.status_code == 200
    assert response_re

    get_password(
        response_re[1]
    )  # Remove password from DB. TODO: Move to DELETE once supported.


def test_get_nonexistant_password():
    """
    Invalid keys should return 404
    """

    key = "invalidkey"
    response = get_password(key)

    assert response.status_code == 404


def test_password_removed():
    """
    POST a new password, GET until view count exceeded and verify 404
    """

    post_response = post_password(1)
    post_response = post_response.json()
    key = re.match(
        r"Added Password at URL: ([A-Za-z0-9]{32})", post_response["Success"]
    )[1]

    get_password(key)
    # TODO: Check for the initial result to ensure the password exists prior to deletion.
    get_response = get_password(key)

    assert get_response.status_code == 404


def test_generate_secret_key():
    """
    Ensure secret key generation matches the expected format.
    """
    key = e_api.generate_secret_key(32)
    assert re.match(r"^[a-zA-Z0-9]{32}$", key)


def test_hash_key():
    """
    Ensure hashing the test secret key matches the expected value.
    """

    key = "ExampleSecretKey"
    prehashed_key = b"\xcd\xda\x81h\xc4\xc8\xac\xd6m\xfa\xff~\xe9@\xc7\xf0\x17q\x9dX"
    hashed_key = e_api.hash_key(key)
    assert hashed_key == prehashed_key