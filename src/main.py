import os
import sys
import random
import string
import hashlib
import logging
from typing import Optional

import pymongo
from Crypto.Cipher import AES
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


class UserPassword(BaseModel):
    """
    Class to hold type information used to encrypt the password.
    """

    password: str
    views: int
    expiration: int  # Hours
    email_addresses: Optional[str] = None


def configure_logging():
    """
    Configure the logging module using environment variables.
    fall back to the logging default if not present.
    """
    log_levels = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]

    try:
        log_level = os.environ["LOG_LEVEL"].upper()
        # validate log_level against supported levels.
        if log_level not in log_levels:
            log_level = "WARNING"
    except KeyError:
        log_level = "WARNING"

    logging.basicConfig(format="%(asctime)s:%(levelname)s:%(message)s", level=log_level)
    logging.debug(f"Configured logger at level {log_level}.")


def get_env_var(var_name, var_text_name, default_value, error_msg=None):
    """
    Try to get the environment variable, and fall back to the default.
    """

    try:
        env_var = os.environ[var_name]
        logging.debug(
            f"MongoDB {var_text_name} set to {env_var} using environment variable."
        )
    except KeyError:
        env_var = default_value
        if error_msg:
            logging.debug(error_msg)
        else:
            logging.debug(f"MongoDB host set to default value: {default_value}")

    return env_var


def get_mongo_config():
    """
    Get the Mongo config information from set environment variables
    fall back to MongoDB default values if not present.
    """

    host = get_env_var("MONGODB_HOST", "host", "localhost")
    port = get_env_var("MONGODB_PORT", "port", 27017)
    timeout = get_env_var("MONGODB_TIMEOUT", "timeout", 5000)
    username = get_env_var(
        "MONGODB_USER", "user", None, "No MongoDB username provided."
    )
    password = get_env_var(
        "MONGODB_PASS", "password", None, "No MongoDB password provided."
    )

    return {
        "host": host,
        "port": port,
        "timeout": timeout,
        "username": username,
        "password": password,
    }


def create_mongo_client():
    """
    Create and return the pymongo client.
    Test to ensure the server is reachable with .server_info()
    """
    mongo_config = get_mongo_config()

    # Exit if no credentials provided.
    if not mongo_config["username"] or not mongo_config["password"]:
        logging.fatal("No MongoDB Credentials provided. Exiting")
        return False

    client = pymongo.MongoClient(
        f"mongodb://{mongo_config['host']}:{mongo_config['port']}/",
        serverSelectionTimeoutMS=mongo_config["timeout"],
        username=mongo_config["username"],
        password=mongo_config["password"],
    )

    # Use server_info() to force a connection to be established to the MongBD server.
    # if no response is received before configured timeout, return False.
    try:
        client.server_info()
        logging.info("Connected to MongoDB server.")
        return client
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.fatal("Unable to connect to MongoDB server. Exiting.")
        return False


def hash_key(key):
    """
    Use SHA1 to hash the key and return the resulting hash.
    """

    sha = hashlib.sha1()
    sha.update(key.encode("utf-8"))
    hashed_key = sha.digest()

    return hashed_key


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

    logging.debug("Generated secret key.")
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
        uuid = hash_key(key)

        logging.debug("Password encrypted.")
        return {
            "uuid": uuid,
            "nonce": nonce,
            "tag": tag,
            "ciphertext": ciphertext,
            "expiration": password.expiration,
            "views": password.views,
        }
    except:
        logging.exception("Unable to encrypt password.")
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
        logging.debug("Password decrypted.")
        return decrypted_password
    except:
        logging.exception("Unable to decrypt password, or verification failed.")
        return False


app = FastAPI()


@app.get("/api/{url}")
def get_password(url):
    """
    Using the URL as the AES key, find the corresponding database entry and decrypt.
    Decrement the view count and remove from database if no views remain.
    """
    uuid = hash_key(url)

    db_entry = mongo_password_col.find_one({"uuid": uuid})
    if not db_entry:
        logging.info("Item not found")
        raise HTTPException(status_code=404, detail="Item not found")

    decrypted_password = decrypt_password_with_url(url, db_entry)
    if not decrypted_password:
        logging.exception("Unable to decrypt password.")
        raise HTTPException(status_code=404, detail="Unable to decrypt password.")
    logging.debug("Accessing password.")
    db_entry["views"] -= 1

    try:
        if db_entry["views"] == 0:  # TODO: or expiration in the past
            mongo_password_col.delete_one({"uuid": uuid})
            logging.info(
                "Password deleted due to no remaining views or expiration time exceeded."
            )
        else:
            mongo_password_col.update_one(
                {"uuid": uuid}, {"$set": {"views": db_entry["views"]}}
            )
            logging.debug("Password views updated.")
    except:
        logging.exception("Unable to update password entry.")
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
        logging.info(f"Password added at URL: {encryption_key}")
        return {"Success": f"Added Password at URL: {encryption_key}"}
    logging.warning("Unable to add new password.")
    raise HTTPException(status_code=404, detail="Unable to add new password.")


configure_logging()

mongo_client = create_mongo_client()
if not mongo_client:
    sys.exit()

db = mongo_client["ephemeral-pass"]
mongo_password_col = db["passwords"]

# API configured and ready to start
logging.info("ephemeral-pass API configuration complete.")