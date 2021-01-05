import os
import sys
import random
import string
import pymongo
from Crypto.Cipher import AES
from fastapi import FastAPI, HTTPException
from typing import Optional
from pydantic import BaseModel


class UserPassword(BaseModel):
    """
    Class to hold information used to encrypt the password.
    """

    password: str
    views: int
    expiration: int  # Hours
    email_addresses: Optional[str] = None


def get_mongo_config():
    """
    Get the Mongo config information from set environment variables
    fall back to MongoDB default values if not present.
    """

    try:
        host = os.environ["MONGODB_HOST"]
    except KeyError:
        host = "localhost"

    try:
        port = os.environ["MONGODB_PORT"]
    except KeyError:
        port = 27017

    try:
        timeout = os.environ["MONGODB_TIMEOUT"]
    except KeyError:
        timeout = 5000

    return {"host": host, "port": port, "timeout": timeout}


def create_mongo_client():
    """
    Create and return the pymongo client.
    Test to ensure the server is reachable with .server_info()
    """
    mongo_config = get_mongo_config()
    client = pymongo.MongoClient(
        f"mongodb://{mongo_config['host']}:{mongo_config['port']}/",
        serverSelectionTimeoutMS=mongo_config["timeout"],
    )

    # Use server_info() to force a connection to be established to the MongBD server.
    # Exit if the server doesn't return within the serverSelectionTimeoutMS.
    try:
        client.server_info()
        return client
    except pymongo.errors.ServerSelectionTimeoutError:
        # Server unavailable.
        sys.exit()


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
            "uuid": key[:5],
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
    db_entry = mongo_password_col.find_one({"uuid": url[:5]})
    if not db_entry:
        raise HTTPException(status_code=404, detail="Item not found")

    decrypted_password = decrypt_password_with_url(url, db_entry)
    if not decrypted_password:
        raise HTTPException(status_code=404, detail="Unable to decrypt password.")

    db_entry["views"] -= 1

    try:
        if db_entry["views"] == 0:  # TODO: or expiration in the past
            mongo_password_col.delete_one({"uuid": url[:5]})
        else:
            mongo_password_col.update_one(
                {"uuid": url[:5]}, {"$set": {"views": db_entry["views"]}}
            )
    except:
        raise HTTPException(status_code=404, detail="Unable to update password entry.")

    return {
        "password": decrypted_password,
        "views": db_entry["views"],
        "expiration": db_entry["expiration"],
    }


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
        mongo_password_col.insert_one(password_entry)
        return {"Success": f"Added Password at URL: {encryption_key}"}
    raise HTTPException(status_code=404, detail="Unable to add new password.")


mongo_client = create_mongo_client()
db = mongo_client["ephemeral-pass"]
mongo_password_col = db["passwords"]
