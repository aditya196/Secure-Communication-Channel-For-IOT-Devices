from iot_security import login_manager
from iot_security.models import User
from iot_security.models import Admin
from iot_security.auth.ECDH import *
from base64 import b64encode
from base64 import b64decode
from flask import redirect, url_for, render_template, current_app
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json
import os
import re
import requests
import ecdsa
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError 

@login_manager.user_loader
def load_user(user_id):
    x = Admin.query.get(user_id)
    if x == None:
        x = User.query.get(user_id)
    return x



def encrypt_msg(data,key):
    data = str(data.ljust(16))
    data = data.encode()
    iv = get_random_bytes(16)
    print('iv :',iv)
    print('key:',key,type(key))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    print(iv)
    return ct,iv


def decrypt_msg(aes_key, iv, cipher_text):
    # aes_key = b64decode(aes_key)
    # iv = b64decode(iv)
    # cipher_text = b64decode(cipher_text)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(cipher_text), AES.block_size)
    print("The message was: ", plaintext)
    plaintext = plaintext.decode()
    return plaintext


def encrypt_key(data):
    key = os.environ.get('ENCRYPT_KEY')
    iv = os.environ.get('ENCRYPT_IV')
    print ('Server Key : ',key)
    key = key.encode()
    iv = iv.encode()
    data = str(data.ljust(16))
    data = data.encode()
    print('iv :',iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    print ('IV :', iv)
    ct = b64encode(ct_bytes).decode('utf-8')
    print ('Encrypted Key :', type(ct))
    return ct


def decrypt_key(cipher_text):
    aes_key= os.environ.get('ENCRYPT_KEY')
    iv = os.environ.get('ENCRYPT_IV')
    aes_key = aes_key.encode()
    iv = iv.encode()
    cipher_text = cipher_text.encode()
    cipher_text = b64decode(cipher_text)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(cipher_text), AES.block_size)
    print ('decrypt iv : ', iv)
    print("The message was: ", plaintext)
    # plaintext = plaintext.decode()
    return plaintext

def clean_key(key):
    key = str(key)
    new_key = re.sub(r'[^A-Za-z0-9,\s]+', '', key)
    return new_key

def generate_ecc_key():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.verifying_key
    return private_key, public_key


def clean_public_keys(key_data):
    key_content = key_data.decode('utf-8')
    key_content = re.sub(r"\n*-----[A-Z]* [A-Z]* [A-Z]*-----\n*","",key_content)
    key_content = key_content.encode()
    return key_content


def sign_data(private_key, message):
    # key should be in bytes
    # message should also be in bytes
    message = message.encode()
    print(private_key)
    private_key = SigningKey.from_pem(private_key)
    signature = private_key.sign(message)
    return signature


def verify_signature(public_key, message, signature):
    message = message.encode()
    public_key = public_key.encode()
    print ('public key :' , public_key)
    public_key = VerifyingKey.from_pem(public_key)
    try:
        public_key.verify(signature, message)
        return True
    except BadSignatureError:
        return False
