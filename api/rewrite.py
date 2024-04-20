from flask import Flask, jsonify, request,abort
import json
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import shutil
from datetime import datetime
from functions import *
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

