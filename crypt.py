# Python3 code below
import os
import base64
import json
from Crypto.Cipher import AES
from phpserialize import loads
import hashlib
import hmac


def decrypt(payload):
    data = json.loads(base64.b64decode(payload))
    key=os.environ['APP_KEY']
    if not valid_mac(key, data):
        return None

    value =  base64.b64decode(data['value'])
    iv = base64.b64decode(data['iv'])

    return unserialize(mcrypt_decrypt(value, iv, key))

def mcrypt_decrypt(value, iv, key):
    AES.key_size=128

    crypt_object=AES.new(key=key,mode=AES.MODE_CBC,IV=iv)
    return crypt_object.decrypt(value)

def unserialize(serialized):
    return loads(serialized)

def valid_mac(key, payload):
    dig = hmac.new(key, digestmod=hashlib.sha256)
    dig.update(data['iv'].encode('utf8'))
    dig.update(data['value'].encode('utf8'))
    dig = dig.hexdigest()
    return dig==payload['mac']