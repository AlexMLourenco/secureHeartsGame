import random
import string
import json
from PyKCS11 import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher , algorithms , modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from OpenSSL import crypto
from cryptography import x509
from secrets import token_bytes

from OpenSSL.crypto import load_certificate, load_privatekey
from OpenSSL.crypto import X509Store, X509StoreContext
from six import u, b, binary_type, PY3
from os import listdir 
from OpenSSL.crypto import load_certificate, load_crl, FILETYPE_ASN1, FILETYPE_PEM, Error, X509Store, X509StoreContext, X509StoreFlags, X509StoreContextError

class DiffieHellman:
    def __init__(self, priv_key):
        self.diffieHellman = priv_key

    def getIV(self):
        return self.IV

    def encrypt(self, public_key, secret):
        self.IV = token_bytes(16)
        shared_key = self.diffieHellman.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(self.IV), backend=default_backend())
        encryptor = aes.encryptor()

        padder = padding.PKCS7(256).padder()
        padded_data = padder.update(secret) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, public_key, secret, iv):
        shared_key = self.diffieHellman.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        decryptor = aes.decryptor()
        decrypted_data = decryptor.update(secret) + decryptor.finalize()

        unpadder = padding.PKCS7(256).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()

class CC:

    def __init__(self):
        lib = '/usr/local/lib/libpteidpkcs11.dylib'
        time_left = 9
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)
         
        if len(self.pkcs11.getSlotList()) == 0:
            print("\nERROR: No card reader detected!")
            raise Exception()
 
        while time_left > 0:
            try:
                self.slot = self.pkcs11.getSlotList(True)[0]
            except:
                if time_left == 9:
                    print("\nAUTH: No card detected! Insert one, seconds left: " + str(time_left), end="\b")
                    sys.stdout.flush()
                else:
                    print(str(time_left), end="\b")
                    sys.stdout.flush()
                time.sleep(1)
                time_left -= 1
            else:
                print("\nAUTH: Detected Citizen Card!")
                break
         
        if time_left == 0:
            print("\nERROR: Could not detect a card, shutting down.")
            raise Exception()
             
 
        self.session = self.pkcs11.openSession(self.slot)

    def get_name(self):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.get_cert())
        return cert.get_subject().commonName
 
    def get_number(self):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.get_cert())
 
        client=cert.get_subject().serialNumber
        if len(client) > 10:
            client = int(client[2:10])
        elif len(client) > 8:
            client = int(client[2:])
 
        return client

    def get_cert(self):
        cert = self.session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0].to_dict()["CKA_VALUE"]
        return crypto.dump_certificate(crypto.FILETYPE_PEM, crypto.load_certificate(crypto.FILETYPE_ASN1, bytes(cert)))

    def get_cert_der(self):
        # just for the CC
        cc_cert = self.session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])[0]
        cc_cert_der = bytes(self.session.getAttributeValue( cc_cert, [CKA_VALUE], True )[0])
        return cc_cert_der

    def sign(self,content):
        return bytes(self.session.sign(self.get_priv_key(), content, Mechanism(CKM_SHA1_RSA_PKCS)))

    def get_priv_key(self):
        return self.session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]

    def get_loaded_cert(self):
        # just for the CC
        cc_cert = self.session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])[0]
        cc_certDer = bytes(self.session.getAttributeValue( cc_cert, [CKA_VALUE], True )[0])
        return x509.load_der_x509_certificate(cc_certDer, default_backend())

    def load_ca(self):
        rootCerts = ()
        trustedCerts = ()
        crlList = ()
        certdir,crldir = "./certs/", "./CRL/"
        for filename in listdir(certdir):
            try:
                cert_info = open(certdir+filename, 'rb').read()
            except IOError:
                print("IO Exception while reading file : {:s} {:s}".format(certdir, filename))
                exit(10)
            else:
                if ".cer" in filename:
                    try:
                        if any(i in filename for i in ["0012","0013","0015"]):
                            certAuth = load_certificate(FILETYPE_PEM, cert_info)
                        elif "Root" in filename:
                            root = load_certificate(FILETYPE_PEM,cert_info)
                        else:
                            certAuth = load_certificate(FILETYPE_ASN1, cert_info)
                    except:
                        print("Exception while loading certificate from file : {:s} {:s}".format(certdir, filename))
                        exit(10)
                    else:
                        trustedCerts = trustedCerts + (certAuth,)
                elif ".crt" in filename:
                    try:
                        if "ca_ecc" in filename or "-self" in filename:
                            root = load_certificate(FILETYPE_PEM, cert_info)
                        else:
                            root = load_certificate(FILETYPE_ASN1, cert_info)
                    except:
                        print("Exception while loading certificate from file : {:s} {:s}".format(
                        certdir, filename))
                        exit(10)
                    else:
                        rootCerts = rootCerts + (root,)
        print("Loaded Root certificates")
        print("Loaded Authentication certificates")
        for filename in listdir(crldir):
            try:
                crl_info = open(crldir + "/" + filename, 'rb').read()
            except IOError:
                print("IO Exception while reading file : {:s} {:s}".format(certdir, filename))
            else:
                if ".crl" in filename:
                    crls = load_crl(FILETYPE_ASN1, crl_info)
            crlList = crlList + (crls,)

        return rootCerts, trustedCerts, crlList

    def cc_store(self):
        rootCerts, trustedCerts, crlList = self.load_ca()
        try:
            cc_store = X509Store()
            for root in rootCerts: cc_store.add_cert(root)
            for trusted in trustedCerts: cc_store.add_cert(trusted)
            for crl in crlList: cc_store.add_crl(crl)
            cc_store.set_flags(X509StoreFlags.CRL_CHECK | X509StoreFlags.IGNORE_CRITICAL)
            return cc_store
        except X509StoreContext:
            print("Store Context description failed")
            return None

''' Extensions:
    OSX     :   .dylib
    ubuntu  :   .os
'''

lib = '/usr/local/lib/libpteidpkcs11.dylib'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load( lib )
slots = pkcs11.getSlotList()

def login():

    print("\n")
    username = input("Username: ")
    slot = pkcs11.getSlotList(tokenPresent=True)[0]
    session = pkcs11.openSession(slot)

    privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),(CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
    signature = bytes(session.sign(privKey, bytes(username, 'utf-8'), Mechanism(CKM_SHA1_RSA_PKCS)))

    return { 'username': username,
            'signature': signature }

def randomSecret(stringLength=20):
    password_characters = string.ascii_letters + string.digits
    return ''.join(random.choice(password_characters) for i in range(stringLength))

def randomUserName(stringLength=5):
    password_characters = string.ascii_letters
    return ''.join(random.choice(password_characters) for i in range(stringLength))

def randomNumber(stringLength=5):
    password_characters = string.digits
    return ''.join(random.choice(password_characters) for i in range(stringLength))

def create_symm_key(pwd):
    salt = b'\ x00'
    kdf = PBKDF2HMAC(hashes.SHA1(), 16, salt, 1000, default_backend())
    return kdf.derive (bytes(pwd, 'UTF-8'))

######################## SYMMETRIC ALGORITHMS ########################

def cipher_with_symm_key_AESCBC(key, data):
    iv=b"k"*16
    cipher = Cipher(algorithms.AES(key) , modes.CBC(iv) , default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize() 

def decipher_with_symm_key_AESCBC(key, data):
    iv=b"k"*16
    cipher = Cipher(algorithms.AES(key) , modes.CBC(iv) , default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize() 

def cipher_with_symm_key_AESOFB(key, data):
    iv=b"k"*16
    cipher = Cipher(algorithms.AES(key) , modes.OFB(iv) , default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize() 

def decipher_with_symm_key_AESOFB(key, data):
    iv=b"k"*16
    cipher = Cipher(algorithms.AES(key) , modes.OFB(iv) , default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize() 

def cipher_with_symm_key_AESCFB(key, data):
    iv=b"k"*16
    cipher = Cipher(algorithms.AES(key) , modes.CFB(iv) , default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize() 

def decipher_with_symm_key_AESCFB(key, data):
    iv=b"k"*16
    cipher = Cipher(algorithms.AES(key) , modes.CFB(iv) , default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize() 

######################## ASYMMETRIC ALGORITHMS ########################

def create_asymmetric_keys():
    priv_key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)
    pub_key = priv_key.public_key()
    return priv_key, pub_key

def create_ecdhe_keys():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    pub_key = private_key.public_key()
    return private_key, pub_key
