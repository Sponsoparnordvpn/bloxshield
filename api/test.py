import requests
import json


def make_service():
    data = {
    "api_key": "shit",
    "service": "Luarmor",
    "prefix": "LUA_",
    "secret_phrase": "Luarmor is so bad",
    "ispremium_response": "luarsuck",
    "notpremium_response": "luarbad",
    "authenticated_response": "luarshit"
}
    url = 'http://127.0.0.1:5000/dev/create_service/'
    response = requests.post(url, json=data)
    print(response.json())




def delservice():
    new = 'http://127.0.0.1:5000/dev/delete_service/'
    data = {
    "api_key": "shit",
    "service": "idiot"
}
    json_data = json.dumps(data)
    headers = {
    'Content-Type': 'application/json'
}
    response = requests.post(new, headers=headers, data=json_data)
    print(response.json())


def changeset():
    new = 'http://127.0.0.1:5000/service_api/modify/'
    data = {
    "api_key": "BS_V1579H3hfPtGSzFnfgoDM2KhwF7jTLTm",
    "service": "LandHub",
    "setting": "authenticated_response",
    "content": "hello"
}
    json_data = json.dumps(data)
    headers = {
    'Content-Type': 'application/json'
}
    response = requests.post(new, headers=headers, data=json_data)
    print(response.json())

def createkye():
    new = 'http://127.0.0.1:5000/service_api/create_key/'
    data = {
    "api_key": "BS_V1579H3hfPtGSzFnfgoDM2KhwF7jTLTm",
    "service": "LandHub",
    "expiration_date": "2024-05-10",
    "premium": True,
    "note": "Custom Note",
    "discordid": "123456789"
}
    json_data = json.dumps(data)
    headers = {
    'Content-Type': 'application/json'
}
    response = requests.post(new, headers=headers, data=json_data)
    print(response.json())

def resethwid():
    new = 'http://127.0.0.1:5000/keys/reset_hwid/'
    data = {
    "api_key": "BS_V1579H3hfPtGSzFnfgoDM2KhwF7jTLTm",
    "service": "LandHub",
    "key" : "LUA_rudQNZ64p",
    "hwid": "haha"
}
    json_data = json.dumps(data)
    headers = {
    'Content-Type': 'application/json'
}
    response = requests.post(new, headers=headers, data=json_data)
    print(response.json())

def exec():
    new = 'http://127.0.0.1:5000/keys/execute/'
    data = {
    "service": "LandHub",
    "key" : "LUA_rudQNZ64p",
}
    json_data = json.dumps(data)
    headers = {
    'Content-Type': 'application/json'
}
    response = requests.post(new, headers=headers, data=json_data)
    print(response)


def script():
    new = 'http://127.0.0.1:5000/scripts/173830303'
    headers = {
    'BS_Access': 'view_src'
}
    params = {
    'service': 'LandHub',
}
    response = requests.get(new, headers=headers, params=params)
    print(response.text)


script()