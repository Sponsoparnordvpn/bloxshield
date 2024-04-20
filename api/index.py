from cryptography.fernet import Fernet
import hashlib
import hmac
import blake3
import secrets
import string
import json
import base64
from flask import Flask, jsonify, request,abort
import json
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import shutil
from datetime import datetime


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























app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
with open("config/bloxshield.json") as file:
    data = json.load(file)
    xor_key = data["xor_key"]
    hmac_key = data["hmac_key"]
    api_key = data["api_key"]

@app.route('/')
def home():
    return "Welcome to BloxShield !"

@app.route('/haha')
def haha():
    return "Bro is dumb"

# Developer API
@app.route('/dev/delete_service/', methods=['POST'])
def delete_service():
    data = request.json
    if not data.get("api_key") or not data.get("service"):
        abort(400)
        
    with open("./config/bloxshield.json", "r") as file:
        config = json.load(file)
        if data["api_key"] != config["api_key"]:
            return jsonify({"success": False, "message": "Incorrect API key"}), 401
    
    service_path = f"./Services/{data['service']}"
    if not os.path.exists(service_path):
        return jsonify({"success": False, "message": "Service does not exist"}), 404
    else:
        try:
            shutil.rmtree(service_path)
            return jsonify({"success": True, "message": "Service deleted successfully"}), 200
        except OSError as e:
            return jsonify({"success": False, "message": str(e)}), 500

@app.route('/dev/get_infos/')
def get_serviceinfos():
    service = request.args.get("service")
    api_key = request.args.get("api_key")
    
    if not service or not api_key:
        abort(400)
    service_path = f"./Services/{service}"
    with open("./config/bloxshield.json", "r") as file:
        config = json.load(file)
        if api_key != config["api_key"]:
            return jsonify({"success": False, "message": "Incorrect API key"}), 401
    if os.path.exists(service_path):
        with open(f"{service_path}/config.json", 'r') as config_file:
            data = json.load(config_file)
            return jsonify({"success": True, "data": data})
    else:
        return jsonify({"success": False, "message": "Service do not exists"}), 404 


@app.route('/dev/create_service/', methods=['POST'])
def create_service():
    data = request.json
    if not data.get("api_key") or not data.get("service"):
        abort(400)
    
        
    with open("./config/bloxshield.json", "r") as file:
        config = json.load(file)
        if data["api_key"] != config["api_key"]:
            return jsonify({"success": False, "message": "Incorrect API key"}), 401
    
    service_path = f"./Services/{data['service']}"
    if os.path.exists(service_path):
        return jsonify({"success": False, "message": "Service already exists"}), 409 
    else:
        try:
            os.makedirs(service_path)
            os.makedirs(f"{service_path}/Scripts")
            
            config_data = {
    "api_key": gen_api_key(),
    "prefix": data["prefix"] if "prefix" in data else "BS_",
    "token_key": data["token_key"] if "token_key" in data else generate_key(16),
    "hash_key": gen_key(data["secret_phrase"]) if "secret_phrase" in data else generate_key(32),
    "encryption_key": generate_key(32),
    "responses": {
        "is_premium": data["ispremium_response"] if "ispremium_response" in data else "1",
        "not_premium": data["notpremium_response"] if "notpremium_response" in data else "0",
        "authenticated": data["authenticated_response"] if "authenticated_response" in data else "1"
    }
}

            with open(f"{service_path}/config.json", 'w') as config_file:
                json.dump(config_data, config_file, indent=4)
            
            keys_data = {}
            with open(f"{service_path}/keys.json", 'w') as keys_file:
                json.dump(keys_data, keys_file, indent=4)

            scripts = {}
            with open(f"{service_path}/scripts.json", 'w') as scriptfile:
                json.dump(scripts, scriptfile, indent=4)
            
            return jsonify({"success": True, "message": "Service created successfully", "config": config_data}), 201
        except OSError as e:
            return jsonify({"success": False, "message": str(e)}), 500


# Member API

@app.route('/service_api/modify/', methods=['POST'])
def modify_config():
    data = request.json
    if not data.get("setting") or not data.get("api_key") or not data.get("service") or not data.get("content"):
        abort(400)

    settings_list = ['prefix', 'token_key', 'hash_key', 'encryption_key', 'premium_response', 'notpremium_response', 'authenticated_response']
    if data["setting"] not in settings_list:
        return jsonify({"success": False, "message": "This setting does not exist!"}), 404
    
    service_path = f"./Services/{data['service']}"
    if not os.path.exists(service_path):
        return jsonify({"success": False, "message": "This service does not exist!"}), 404
    
    with open(f"{service_path}/config.json", "r") as file:
        config = json.load(file)
        if data["api_key"] != config["api_key"]:
            return jsonify({"success": False, "message": "Incorrect API key"}), 401
        else:
            if data["setting"] == "premium_response":
                config["responses"]["is_premium"] = data["content"]
            elif data["setting"] == "notpremium_response":
                config["responses"]["not_premium"] = data["content"]
            elif data["setting"] == "authenticated_response":
                config["responses"]["authenticated"] = data["content"]
            else:
                config[data["setting"]] = data["content"]
    
    with open(f"{service_path}/config.json", "w") as file:
        json.dump(config, file, indent=4)
    
    return jsonify({"success": True, "message": "Configuration updated successfully"}), 200

@app.route('/service_api/delete_key/', methods=["POST"])
def delkey():
    data = request.json
    api_key = data.get("api_key")
    service = data.get("service")
    key = data.get("key")
    if not api_key or not service or not key:
        abort(400)
    service_path = f"./Services/{data['service']}"
    if not os.path.exists(service_path):
        return jsonify({"success": False, "message": "This service does not exist!"}), 404
    
    with open(f"{service_path}/config.json", "r") as file:
        config = json.load(file)
        if data["api_key"] != config["api_key"]:
            return jsonify({"success": False, "message": "Incorrect API key"}), 401
        else:
            with open(f"{service_path}/keys.json", "r") as keyfile:
                keys = json.load(keyfile)
                if key in keys:
                    del keys[key]
                else:
                    return jsonify({"success": False, "message": "Key not found !"}), 404
            with open(f"{service_path}/keys.json", "w") as keyfiletwp:
                json.dump(keys, keyfiletwp, indent=4)
            return jsonify({"success": True, "message": "Key deleted succesfully !"}), 200

            

@app.route('/service_api/create_key/', methods=['POST'])
def create_key():
    data = request.json
    if not data.get("api_key") or not data.get("service") or not data.get("expiration_date"):
        abort(400)
    
    service_path = f"./Services/{data['service']}"
    if not os.path.exists(service_path):
        return jsonify({"success": False, "message": "This service does not exist!"}), 404
    
    with open(f"{service_path}/config.json", "r") as file:
        config = json.load(file)
        if data["api_key"] != config["api_key"]:
            return jsonify({"success": False, "message": "Incorrect API key"}), 401
        else:
            try:
                prefix = config["prefix"]
                name = generate_scriptkey(prefix)
                print(name)
                with open(f"{service_path}/keys.json", "r") as f:
                    keys = json.load(f)
                    premium = "false" if not data.get("premium") else data.get("premium")
                    note = "Default Note" if not data.get("note") else data.get("note")
                    discord_id = "None" if not data.get("discordid") else data.get("discordid")
                    keys[name] = {
                            "hwid": "None",
                            "expiration_date": data.get("expiration_date"),
                            "note": note,
                            "premium": premium,
                            "discord_id": discord_id,
                            "total_resets": 0,
                            "total_executions": 0
                }
                    with open(f"{service_path}/keys.json", "w") as newf:
                        json.dump(keys, newf,  indent=4)
                    return jsonify({"success": True, "message": "Key created succesfully !", "data": keys[name]}), 200
            except Exception as e:
                return jsonify({"success": False, "message": str(e)}), 401


@app.route('/service_api/get_data/')
def getkeydata():
    api_key = request.args.get("api_key")
    service = request.args.get("service")
    key = request.args.get("key")
    if not api_key or not service or not key:
        abort(400)
    service_path = f"./Services/{service}"
    if not os.path.exists(service_path):
        return jsonify({"success": False, "message": "This service does not exist!"}), 404
    
    with open(f"{service_path}/config.json", "r") as file:
        config = json.load(file)
        if api_key != config["api_key"]:
            return jsonify({"success": False, "message": "Incorrect API key"}), 401
        else:
            with open(f"{service_path}/keys.json", "r") as keyfile:
                keys = json.load(keyfile)
                if key in keys:
                    return jsonify({"success": True, "data": keys[key]}), 200
                else:
                    return jsonify({"success": False, "message": "Key not found !"}), 404
                





# Users related

@app.route('/scripts/<id>')
def loadstring(id):
    print(id)
    service = request.args.get("service")
    id = str(id)
    service_path = f"./Services/{service}"
    if not os.path.exists(service_path):
            return jsonify({"success": False, "message": "This service does not exist!"}), 404
    with open(f"{service_path}/scripts.json", "r") as file:
            scripts = json.load(file)
            print(scripts)
            if scripts[id]:
                src = scripts[id]["src"]
                with open(f"{src}", "r") as source:
                   return source.read()
            else:
                abort(404) 

@app.route('/keys/reset_hwid/', methods=['POST'])
@limiter.limit("1 per hour")
def reset_hwid():
    data = request.json
    if not data.get("api_key") or not data.get("service") or not data.get("key"):
        abort(400)
    
    service_path = f"./Services/{data['service']}"
    if not os.path.exists(service_path):
        return jsonify({"success": False, "message": "This service does not exist!"}), 404
    
    with open(f"{service_path}/config.json", "r") as file:
        config = json.load(file)
        if data["api_key"] != config["api_key"]:
            return jsonify({"success": False, "message": "Incorrect API key"}), 401
        else:
            try:
                hwid = "None" if not data.get("hwid") else data.get("hwid")
                with open(f"{service_path}/keys.json", "r") as file:
                    keys = json.load(file)
                    if keys[data.get("key")]:
                        keys[data.get("key")]["hwid"] = hwid
                        keys[data.get("key")]["total_resets"] =  keys[data.get("key")]["total_resets"] + 1
                    else:
                        return jsonify({"success": False, "message": "Key does not exists!"}), 404
                with open(f"{service_path}/keys.json", "w") as newf:
                    json.dump(keys, newf, indent=4)
                    return  jsonify({"success": True, "message": "HWID reseted succesfully !"}), 200
            except Exception as e:
                return jsonify({"success": False, "message": str(e)}), 401
            
@app.route('/keys/execute/', methods=['POST'])
@limiter.limit("1 per minute")
def on_execute():
    data = request.json
    if not data.get("service") or not data.get("key"):
        abort(400)
    service_path = f"./Services/{data['service']}"
    if not os.path.exists(service_path):
        return jsonify({"success": False, "message": "This service does not exist!"}), 404
    try:
        with open(f"{service_path}/keys.json", "r") as file:
            data = json.load(file)
            if data[data.get("key")]:
                data[data.get("key")]["total_executions"] = data[data.get("key")]["total_executions"] + 1
                return  jsonify({"success": True, "message": "Key executed succesfully"}), 200
            else:
                return jsonify({"success": False, "message": "Key not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 401






@app.route('/keys/authenticate/')
def validate():
    service = request.args.get("service")
    service_path = f"./Services/{service}"
    token = request.args.get("token")

    if os.path.exists(service_path):
        try:
            with open(f'{service_path}/config.json', 'r') as config:
                configuration = json.load(config)
                xor_key = configuration["token_key"]
                cipher_key = configuration["encryption_key"]
                hash_key = configuration["hash_key"]
                premium_response = configuration["responses"]["is_premium"]
                not_premiumrs = configuration["responses"]["not_premium"]
                authenticated = configuration["responses"]["authenticated"]





            token_data = json.loads(xor(base64decode(token), xor_key))
            if token_data["service"] == service and token_data["key"] and token_data["hwid"]:
                key = token_data["key"]
                hwid = token_data["hwid"]
                with open(f'{service_path}/keys.json', 'r') as file:
                    keys = json.load(file)
                if key in keys:
                    print(keys[key]["hwid"])
                    if keys[key]["hwid"] == "None":
                        keys[key]["hwid"] = hwid
                        with open(f'{service_path}/keys.json', 'w') as newfile:
                                json.dump(keys, newfile, indent=4)

                    expiration_date = datetime.strptime(keys[key]["expiration_date"], "%Y-%m-%d") if 'expiration_date' in keys[key] else None
                    current_date = datetime.now()
                    if not expiration_date or current_date <= expiration_date:
                        if keys[key]["hwid"] == hwid:
                            premium = premium_response if keys[key]["premium"] == "true" else not_premiumrs
                            isPremium = vigenere_encrypt("isPremium", cipher_key)
                            statusTitle = vigenere_encrypt("status", cipher_key)
                            hwidTitle = vigenere_encrypt("hwid", cipher_key)
                            status = authenticated
                            new_data = {
                                        "success" : True,
                                        "service" : service,
                                        "data" : {
                                            hwidTitle : hwid,
                                            isPremium : hash(premium,"hmac_sha512", hash_key),
                                            "note" : keys[key]["note"],
                                            "expiresAt" : keys[key]["expiration_date"],
                                            statusTitle : hash(status,"hmac_sha512", hash_key)
                                        }
                                }
                            return jsonify(new_data), 200
                        else:
                            return jsonify({"success": False, "message": "HWID mismatch"}), 401
                    else:
                        with open(f'{service_path}/keys.json', 'r') as file:
                                expireaa = json.load(file)
                                del expireaa[key]
                        with open(f'{service_path}/keys.json', 'w') as newfile:
                                json.dump(expireaa, newfile, indent=4)
                        return jsonify({"success": False, "message": "Key expired"}), 401
                else:
                    return jsonify({"success": False, "message": "Invalid key"}), 401
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 401

    return jsonify({"success": False, "message": "Something went wrong."}), 400





if __name__ == '__main__':
    app.run(debug=True)

