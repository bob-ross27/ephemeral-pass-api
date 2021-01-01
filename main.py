from os import stat
import random
import string
from Crypto.Cipher import AES
from fastapi import FastAPI, HTTPException
from typing import Optional
from pydantic import BaseModel


class UserPassword(BaseModel):
    """
    Class to hold type information used to encrypt the password.
    """

    password: str
    views: int
    expiration: int  # Hours
    email_addresses: Optional[str] = None


def generate_secret_key(length):
    """
    Generate a random string of characters.
    """
    secret_key = "".join(
        random.SystemRandom().choice(
            string.ascii_uppercase + string.ascii_lowercase + string.digits
        )
        for _ in range(length)
    )

    return secret_key


def encrypt_password(password, key):
    """
    Generate a secret key for encryption usage, and encrypt the user provided string.
    Return an object for storage in the DB.
    This ensures the database doesn't know the key directly, only a subset used as the ID for lookup purposes.
    """
    plaintext_password = password.password
    try:
        cipher = AES.new(key.encode("utf-8"), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_password.encode("utf-8"))
        nonce = cipher.nonce

        return {
            "id": key[:5],
            "nonce": nonce,
            "tag": tag,
            "ciphertext": ciphertext,
            "expiration": password.expiration,
            "views": password.views,
        }
    except:
        return False


def decrypt_password_with_url(input_url, db_entry):
    """
    Using the user provided URL as the key - decrypt the ciphertext stored in the DB.
    Return the decrypted string.
    """
    try:
        cipher_decrypt = AES.new(
            input_url.encode("utf-8"), AES.MODE_EAX, db_entry["nonce"]
        )
        decrypted_password = cipher_decrypt.decrypt_and_verify(
            db_entry["ciphertext"], db_entry["tag"]
        )
        return decrypted_password
    except:
        return False


app = FastAPI()


@app.get("/api/{url}")
def get_password(url):
    """
    Using the URL as the AES key, find the corresponding database entry and decrypt.
    Decrement the view count and remove from database if no views remain.
    """
    db_entry = [x for x in db if x["id"] == url[:5]]
    if db_entry:
        try:
            db_entry = db_entry[0]

            db_entry["views"] -= 1
            decrypted_password = decrypt_password_with_url(url, db_entry)
            if not decrypted_password:
                raise HTTPException(
                    status_code=404, detail="Unable to decrypt password."
                )

            return_body = {
                "password": decrypted_password,
                "views": db_entry["views"],
                "expiration": db_entry["expiration"],
            }

            if db_entry["views"] == 0:  # TODO: or expiration in the past
                db.remove(db_entry)

            return return_body
        except:
            raise HTTPException(status_code=404, detail="Unable to decrypt password.")
    else:
        raise HTTPException(status_code=404, detail="Item not found")


@app.post("/api/new")
def post_password(password: UserPassword):
    """
    Parse the JSON body and encrypt the provided password.
    Add the ciphertext and associated fields to the database, and return
    the AES key to the user as the URL.
    """
    encryption_key = generate_secret_key(32)
    password_entry = encrypt_password(password, encryption_key)
    if password_entry:
        db.append(password_entry)
        return {"Success": f"Added Password at URL: {encryption_key}"}
    raise HTTPException(status_code=404, detail="Unable to add new password.")


db = []