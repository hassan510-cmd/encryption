from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from os import urandom
from base64 import b64encode
from cryptography.fernet import Fernet
import os


def encrypt():
    global original_message
    global OriginalByteMessage
    original_message = input("Enter Code : ")
    OriginalByteMessage = original_message.encode()
    randomKey = urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=randomKey,
        iterations=100000,
        backend=default_backend()
    )

    EncryptedByteMessage = base64.urlsafe_b64encode(kdf.derive(OriginalByteMessage))

    global f 
    f = Fernet(EncryptedByteMessage)
    encryptedKeyForByteMessage = f.encrypt(OriginalByteMessage)
    print("Key : ", encryptedKeyForByteMessage)

def decrypt():
    key = input("Enter key : ")
    KeyByte =  key.encode()
    decrypted = f.decrypt(KeyByte)
    original2 = decrypted.decode()
    print(original2)


encrypt()
decrypt()
# Use one of the methods to get a key (it must be the same when decrypting)

# ____________________________________________________________________________________
# # deal with file
# def ecryptFiles(secrectKey,palinPath,outputPath):
#     "Make sure your key must be bytes OR generated from Fernet.generate_key()"
#     secrectKey = b'Wfv1CQ1-Fhf5oNJvaRidE8GejB3yb3tyydLWfeowYnQ='
#     print(secrectKey)
    
#     with open(palinPath, 'rb') as f:
#         data = f.read()

#     fernet = Fernet(secrectKey)
#     encrypted = fernet.encrypt(data)

#     with open(outputPath, 'wb') as f:
#         f.write(encrypted)


# def decryptFiles(secrectKey, encryptedPath, outputPath):
#     "Make sure your key must be bytes OR generated from Fernet.generate_key()"
#     secrectKey = b'Wfv1CQ1-Fhf5oNJvaRidE8GejB3yb3tyydLWfeowYnQ='
#     print(secrectKey)
    
#     with open(encryptedPath, 'rb') as f:
#         data = f.read()

#     fernet = Fernet(secrectKey)
#     decrypted = fernet.decrypt(data)

#     with open(outputPath, 'wb') as f:
#         f.write(decrypted)
    



# x = "awesome"

# print(id(x))    
# def myfunc():
#   global x
#   x = "fantastic"

# myfunc()

# def ff():
#     f=x+"d"
#     print(f)
#     print(id(x))
# ff()
# print("Python is " + x)