import os
import base64
import json
from Crypto.Cipher import AES
from phpserialize import loads
import hashlib
import hmac


def decrypt(payload, key):
    """
    Decrypt strings that have been encrypted using Laravel's encrypter (AES-256 encryption).

    Plain text is encrypted in Laravvel using the following code:
    >>> ciphertext = Crypt::encrypt('hello world');

    The ciphertext is a base64's json-encoded array consisting of the following keys:
       [
          'iv' => 'generated initialization vector (iv)',
          'value' => 'encrypted, base64ed, signed value',
          'mac'  => 'message authentication code (mac)'
       ]

    The 'value' is signed using a message authentication code (MAC) so verify that the value has not changed during
    transit.

    Parameters:
    payload (str): Laravel encrypted text.
    key (str): Encryption key (base64 decoded). Make sure 'base64:' has been removed from string.

    Returns:
    str: plaintext
    """

    data = json.loads(base64.b64decode(payload))
    if not valid_mac(key, data):
        return None

    value = base64.b64decode(data['value'])
    iv = base64.b64decode(data['iv'])

    return unserialize(mcrypt_decrypt(value, iv, key)).decode("utf-8")

def mcrypt_decrypt(value, iv, key):
    AES.key_size=128
    crypt_object=AES.new(key=key,mode=AES.MODE_CBC,IV=iv)
    return crypt_object.decrypt(value)

def unserialize(serialized):
    return loads(serialized)

def valid_mac(key, data):
    dig = hmac.new(key, digestmod=hashlib.sha256)
    dig.update(data['iv'].encode('utf8'))
    dig.update(data['value'].encode('utf8'))
    dig = dig.hexdigest()
    return dig==data['mac']
