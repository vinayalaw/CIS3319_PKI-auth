#FILENAME: pki_util.py
#AUTHOR: Vinayak Desai
#####################################################
#imports
import pickle
import des
import rsa
from des import DesKey

#####################################################
#functions
def generateRsaKeys():
    return rsa.newkeys(512)

def generateDesKey(seedString):
    bString = bytes(seedString)
    key = DesKey(bString)
    return key

def rsaEncrypt(plaintext, pub_key):
    cyphertext = rsa.encrypt(plaintext, pub_key)
    return cyphertext

def rsaDecrypt(cyphertext, priv_key):
    plaintext = rsa.decrypt(cyphertext, priv_key)
    return plaintext

def desEncrypt(plaintext, key):
    bString = bytes(plaintext)
    cyphertext = key.encrypt(bString, padding=True)
    return cyphertext

def desDecrypt(cyphertext, key):
    plaintext = key.decrypt(cyphertext, padding=True)
    return plaintext

def pack(message):
    return pickle.dumps(message)

def unpack(message):
    return pickle.loads(message)

#####################################################