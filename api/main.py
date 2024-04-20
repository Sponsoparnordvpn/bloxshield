from flask import Flask, jsonify, request
import json
from datetime import datetime
import os
from functions import * 
app = Flask(__name__)

with open("config/bloxshield.json") as file:
    data = json.load(file)
    xor_key = data["xor_key"]
    hmac_key = data["hmac_key"]
    api_key = data["api_key"]




@app.route('/service_api')
def getsettings():
    service = request.args.get("service")
    command = request.args.get("command")
    if command == "getconfig":
        with open('databases/services.json', 'r') as file:
            data = json.load(file)
        
            service = xor(service,xor_key)
            print(service)

        if service in data:
            
            new = {
                  "api_key" : hash(data[service]["api_key"], "blake3"),
                  "display" : data[service]["display"],
                  "discord" : data[service]["discord"],
                  "authmode" : hash(data[service]["mode"], "md5")
            }
         
            return jsonify(new), 200
        else:
            return "Service not found", 404

@app.route('/<service_name>/api/validate')
def validate2(service_name):
    key = request.args.get("key")
    token = request.args.get("token")
    service_name = xor(service_name, xor_key)
    service_path = f"./Services/{service_name}"

    if os.path.exists(service_path):
        try:
            with open(f"{service_path}/keys.json") as f:
                data = json.load(f)
                if key in data:
                    if data[key]["hwid"] == token:
                        return jsonify({"success": True, "message": "Validation successful"}), 200
                    else:
                        return jsonify({"success": False, "message": "Invalid token"}), 401
                else:
                    return jsonify({"success": False, "message": "Invalid key"}), 401
        except FileNotFoundError:
            return jsonify({"success": False, "message": "keys.json not found"}), 500
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500
    else:
        return jsonify({"success": False, "message": "Service not found"}), 404



@app.route('/api/validate')
def validate():
    service = request.args.get("service")
    key = request.args.get("key")
    auth = request.args.get("auth")

    try:
        with open("databases/keys.json") as f:
            data = json.load(f)
            service = xor(service, xor_key)
            if service in data:
                if key in data[service]:
                    if data[service][key]["hwid"] == auth:
                        if data[service][key]["blacklisted"] == "false":
                            if "expiration_date" in data[service][key]:
                                expiration_date = datetime.strptime(data[service][key]["expiration_date"], "%Y-%m-%d") if 'expiration_date' in data[service][key] else None
                                current_date = datetime.now()
                                if not expiration_date or current_date <= expiration_date:
                                    premium = "0001" if data[service][key]["premium"] == "true" else "0000"
                                    status = key + data[service][key]["hwid"]
                                    new_data = {
                                        "success" : False,
                                        "service" : request.args.get("service"),
                                        "data" : {
                                            "hwid" : auth,
                                            "isPremium" : hash(premium,"hmac_sha512", hmac_key),
                                            "note" : data[service][key]["note"],
                                            "expiresAt" : data[service][key]["expiration_date"],
                                            "status" : hash(status,"hmac_sha512", hmac_key)
                                        }
                                    }
                                    return jsonify(new_data), 200
                                else:
                                    return jsonify({"success": False, "message": "Key expired"}), 200
                            else:
                                return jsonify({"success": False, "message": "Expiration date not found"}), 400
                        else:
                            return jsonify({"success": False, "message": "Key is blacklisted"}), 403
                    else:
                        return jsonify({"success": False, "message": "Invalid authentication"}), 401
                else:
                    return jsonify({"success": False, "message": "Key not found"}), 404
            else:
                return jsonify({"success": False, "message": "Service not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@app.route('/service_api/delete_service')
def delete_service():
    service = request.args.get("service")
    key = request.args.get("api_key")
    
    if key != api_key:
        return jsonify({"success": False, "message": "API key is incorrect"}), 404
    
    with open("databases/services.json", "r") as file:
        data = json.load(file)
        if service in data:
            del data[service]
        else:
            return jsonify({"success": False, "message": "Service not found"}), 404
    
    with open("databases/services.json", "w") as file:
        json.dump(data, file, indent=4)
    
    with open("databases/keys.json", "r") as file:
        data = json.load(file)
        if service in data:
            del data[service]
        else:
            return jsonify({"success": False, "message": "Service not found"}), 404
    
    with open("databases/keys.json", "w") as file:
        json.dump(data, file, indent=4)
    
    return jsonify({"success": True, "message": "Service deleted successfully"})


@app.route('/service_api/create_service', methods=['POST'])
def create_service():
    request_data = request.json
    service = request_data.get("service")
    display = request_data.get("display")
    discord = request_data.get("discord")
    mode = request_data.get("mode")
    prefix = request_data.get("prefix")
    key = request_data.get("api_key")
    
    if key != api_key:
        return jsonify({"success": False, "message": "API key is incorrect"}), 400
    
    with open("databases/services.json", "r+") as services_file, open("databases/keys.json", "r+") as keys_file:
        services_data = json.load(services_file)
        keys_data = json.load(keys_file)
        
        if service in services_data or service in keys_data:
            return jsonify({"success": False, "message": "Service already exists"}), 409
        
        api_key_generated = gen_api_key()
        
        services_data[service] = {
            "api_key": api_key_generated,
            "display": display or None,
            "discord": discord or "https://discord.gg/32pZJfSDKm",
            "mode": mode or None,
            "prefix" : prefix or "BS_"
        }
        
        keys_data[service] = {
        }
        
        services_file.seek(0)
        json.dump(services_data, services_file, indent=4)
        services_file.truncate()
        
        keys_file.seek(0)
        json.dump(keys_data, keys_file, indent=4)
        keys_file.truncate()
    
    return jsonify({"success": True, "message": "Service created successfully"}), 200

@app.route('/service_api/set_discord',methods=['POST'])
def set_discord():
    request_data = request.json
    service = request_data.args.get("service")
    api_key = request_data.args.get("api_key")
    discord = request_data.args.get("discord")
    with open("databases/services.json") as file:
        data = json.load(file)
        if not data.get(service):
            return jsonify({"success": False, "message": "Service not found"}), 404
        key = data[service]["api_key"]
        
    if api_key != key:
        return jsonify({"success": False, "message": "API key is incorrect"}), 400
   
    data[service]["discord"] = discord

    with open("databases/services.json", "w") as f:
        json.dump(data, f, indent=4)
    return jsonify({"success": True, "message": "Succesfully changed discord"}), 200



@app.route('/service_api/set_display',methods=['POST'])
def set_display():
    request_data = request.json
    service = request_data.args.get("service")
    api_key = request_data.args.get("api_key")
    display = request_data.args.get("display")
    with open("databases/services.json") as file:
        data = json.load(file)
        if not data.get(service):
            return jsonify({"success": False, "message": "Service not found"}), 404
        key = data[service]["api_key"]
        
    if api_key != key:
        return jsonify({"success": False, "message": "API key is incorrect"}), 400
    
    data[service]["display"] = display

    with open("databases/services.json", "w") as f:
        json.dump(data, f, indent=4)
    return jsonify({"success": True, "message": "Succesfully changed service display name"}), 200


@app.route('/service_api/set_mode',methods=['POST'])
def set_mode():
    request_data = request.json
    service = request_data.args.get("service")
    api_key = request_data.args.get("api_key")
    mode = request_data.args.get("mode")
    if mode not in ["fingerprint", "hwid", "IP"]:
        return jsonify({"success": False, "message": "Authentication type is incorrect"}), 400
    with open("databases/services.json") as file:
        data = json.load(file)
        if not data.get(service):
            return jsonify({"success": False, "message": "Service not found"}), 404
        key = data[service]["api_key"]
    if api_key != key:
        return jsonify({"success": False, "message": "API key is incorrect"}), 400
    
    data[service]["mode"] = mode

    with open("databases/services.json", "w") as f:
        json.dump(data, f, indent=4)
    return jsonify({"success": True, "message": "Succesfully changed authentication type"}), 200
        
@app.route('/service_api/set_prefix', methods=['POST'])
def set_prefix():
    request_data = request.json
    service = request_data.args.get("service")
    api_key = request_data.args.get("api_key")
    prefix = request_data.args.get("prefix")
    with open("databases/services.json") as file:
        data = json.load(file)
        if not data.get(service):
            return jsonify({"success": False, "message": "Service not found"}), 404
        key = data[service]["api_key"]
    if api_key != key:
        return jsonify({"success": False, "message": "API key is incorrect"}), 400
    
    data[service]["prefix"] = prefix

    with open("databases/services.json", "w") as f:
        json.dump(data, f, indent=4)
    return jsonify({"success": True, "message": "Succesfully changed prefix"}), 200

if __name__ == '__main__':
    app.run(debug=True)
    

