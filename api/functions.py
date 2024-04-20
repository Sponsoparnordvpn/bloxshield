#functions.py
from cryptography.fernet import Fernet
import hashlib
import hmac
import blake3
import secrets
import string
import json
import base64

def generate_key(length):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_scriptkey(prefix, length=16):
    alphabet = string.ascii_letters + string.digits
    return prefix + ''.join(secrets.choice(alphabet) for _ in range(length))



def repeat_key(key, length):
    if len(key) >= length:
        return key[:length]

    times = length // len(key)
    remain = length % len(key)

    result = ''

    for i in range(times):
        result += key

    if remain > 0:
        result += key[:remain]

    return result

def xor(message, key):
    rkey = repeat_key(key, len(message))

    result = ''

    for i in range(len(message)):
        k_char = rkey[i]
        m_char = message[i]

        k_byte = ord(k_char)
        m_byte = ord(m_char)

        xor_byte = m_byte ^ k_byte

        xor_char = chr(xor_byte)

        result += xor_char

    return result



def base64encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    encoded_bytes = base64.b64encode(data)
    return encoded_bytes.decode('utf-8')


def base64decode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    decoded_bytes = base64.b64decode(data)
    return decoded_bytes.decode('utf-8')

def gen_api_key(length=32):
    alphabet = string.ascii_letters + string.digits
    api_key = ''.join(secrets.choice(alphabet) for _ in range(length))
    return "BS_" + api_key
def gen_key(phrase):
    phrase_bytes = phrase.encode('utf-8')
    
    sha256_hash = hashlib.sha256(phrase_bytes).hexdigest()

    return sha256_hash[:32]

def gen_fernet_key():
    return Fernet.generate_key()

def hash(data, hash_type, key=None):
    if hash_type == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(data.encode()).hexdigest()
    elif hash_type == "sha512":
        return hashlib.sha512(data.encode()).hexdigest()
    elif hash_type == "hmac_sha256":
        if key:
            return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
        else:
            return "Key is required for HMAC-SHA256"
    elif hash_type == "hmac_sha512":
        if key:
            return hmac.new(key.encode(), data.encode(), hashlib.sha512).hexdigest()
        else:
            return "Key is required for HMAC-SHA512"
    elif hash_type == "blake3":
        return blake3.blake3(data.encode()).hexdigest()
    else:
        return "Unsupported hash type"

def jsonencode(data,key):
    fernet = Fernet(key)
    return fernet.encrypt(data)

def jsondecode(data,key):
    fernet = Fernet(key)
    return fernet.decrypt(data)


def xor(message, key):
    encrypted = ""
    key_index = 0
    for char in message:
        xor_result = ord(char) ^ ord(key[key_index])
        encrypted += chr(xor_result)
        key_index = (key_index + 1) % len(key)
    return encrypted

def generate_vigenere_table():
    table = []
    for i in range(26):
        table.append([chr((j + i) % 26 + ord('A')) for j in range(26)])
    return table

def vigenere_encrypt(plain_text, key):
    table = generate_vigenere_table()
    key = key.upper()
    key_index = 0
    cipher_text = ""
    for char in plain_text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if char.islower():
                cipher_text += table[ord(char.upper()) - ord('A')][shift].lower()
            else:
                cipher_text += table[ord(char.upper()) - ord('A')][shift]
            key_index += 1
        else:
            cipher_text += char
    return cipher_text

def is_cipher(text):
    text = text.upper()
    for char in text:
        if char.isalpha():
            return True
    return False


def vigenere_decrypt(cipher_text, key):
    table = generate_vigenere_table()
    key = key.upper()
    key_index = 0
    plain_text = ""
    for char in cipher_text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            decrypted_char = ''
            for i in range(26):
                if table[i][shift] == char.upper():
                    decrypted_char = table[i][0]
                    break
            if char.islower():
                plain_text += decrypted_char.lower()
            else:
                plain_text += decrypted_char
            key_index += 1
        else:
            plain_text += char
    return plain_text


def is_base64(x):
    try:
        x = x.encode('utf-8')
        x = base64.b64decode(x)
        return True
    except:
        return False
