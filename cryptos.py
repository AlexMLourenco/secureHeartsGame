import random
import string
from PyKCS11 import *
from cryptography.hazmat.primitives.ciphers import Cipher , algorithms , modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

''' Extensions:
    OSX     :   .dylib
    ubuntu  :   .os
'''
lib = '/usr/local/lib/libpteidpkcs11.dylib'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load( lib )
slots = pkcs11.getSlotList()

def login():

    #if len(pkcs11.getSlotList()) == 0:
    #    print("\nERROR: No card reader detected!")
    #    raise Exception()

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

def create_symm_key(pwd):
    salt = b'\ x00'
    kdf = PBKDF2HMAC(hashes.SHA1(), 16, salt, 1000, default_backend())
    return kdf.derive (bytes(pwd, 'UTF-8'))

def cipher_with_symm_key(key, data):
    iv=b"k"*16
    cipher = Cipher(algorithms.AES(key) , modes.CBC(iv) , default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize() 

def decipher_with_symm_key(key, data):
    iv=b"k"*16
    cipher = Cipher(algorithms.AES(key) , modes.CBC(iv) , default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize() 

def create_asymmetric_keys():
    priv_key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)
    pub_key = priv_key.public_key()
    return priv_key, pub_key

def cipher_asymmetric_key(pub_key, data):
    return pub_key.encrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

def decipher_asymmetric_key(priv_key, data):
    return priv_key.decrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

'''
	def get_cert(self):
		cert = self.session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0].to_dict()["CKA_VALUE"]
		return crypto.dump_certificate(crypto.FILETYPE_PEM, crypto.load_certificate(crypto.FILETYPE_ASN1, bytes(cert)))

	def get_privKey(self):
		return self.session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]

	def signdict(self,ddict):
		jdict=json.dumps(ddict,sort_keys=True)
		return self.sign(jdict)

	def sign(self, data):
		return bytes(self.session.sign(self.get_privKey(), data, Mechanism(CKM_SHA1_RSA_PKCS)))


	def get_pubKey_cert(cert):
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
		pubKey = crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey())
		return pubKey

	def get_Name(cert):
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
		return cert.get_subject().commonName

	def get_CCNumber(cert):
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

		client=cert.get_subject().serialNumber
		if len(client) > 10:
			client = int(client[2:10])
		elif len(client) > 8:
			client = int(client[2:])

		return client
'''