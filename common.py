import constants
import base64
import json
from cryptos import *
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
import sys, traceback

def encodeContent (content):
    return json.dumps(content).encode()

def sendContent( content, priv_key, sessionKey=None, encrypt=True, sessionUserIdx=-1, cc = None, sessionUserOriginIdx = -1): 
    
    try:

        content = content if type(content) is dict  else json.loads(content.decode())

        if (constants.DEBUG_MODE):
            printMessage("SENDING CONTENT  |  " + content[constants.KEY_ACTION])  

        if encrypt:

            # Here we will create a specific structure to sign the data 
            data = {}
            data[constants.KEY_UNSIGNED_DATA] = content

            if (cc):         
                unsigned = bytes( json.dumps(content,sort_keys=True) , 'utf-8')
                data[constants.KEY_SIGNED_DATA] = base64.b64encode(cc.sign(unsigned)).decode("utf8").replace("'",'"')        
                data[constants.KEY_CERTIFICATE] = base64.b64encode(cc.get_cert_der()).decode("utf8").replace("'",'"')      
        
            # Make a json of the content          
            unsigned = json.dumps(data).encode('utf-8')

            #O conteudo a cifrar tem de ser multiplo de 16 senao a cifra nao funciona
            if (len(unsigned) % 16 != 0):
                block = int(len(unsigned)/16)
                block = (block + 1) * 16
                unsigned = unsigned.ljust(block)
            else:
                block = 0       


            command = {}

            if (sessionKey == None):
                signed = priv_key.sign(unsigned, ec.ECDSA(hashes.SHA256())) 
                command [constants.KEY_SIGNED_CONTENT ] = base64.b64encode(signed).decode("utf8").replace("'",'"')
                command [constants.KEY_UNSIGNED_CONTENT ] = base64.b64encode(unsigned).decode("utf8").replace("'",'"')
            else:
                dh = DiffieHellman(priv_key)
                signed = dh.encrypt(sessionKey, unsigned)
                command [constants.KEY_SIGNED_CONTENT ] = base64.b64encode(signed).decode("utf8").replace("'",'"')
                command [constants.KEY_IV] = base64.b64encode(dh.getIV()).decode("utf8").replace("'",'"')
                command [constants.KEY_SESSION_ORIGIN_IDX] = sessionUserOriginIdx

            command[constants.KEY_CIPHERED_PLAYER_IDX] =  sessionUserIdx
           
            content = command
        else:
            pass

        
        #Passar o objeto de python para json 
        command = json.dumps(content).encode()
        return command

    except Exception:
        print("Exception in user code:")
        print("-"*60)
        traceback.print_exc(file=sys.stdout)
        print("-"*60)
        sys.exit(0)

    return None

def receiveContent(content, pub_key, priv_key = None, origin_pub_key= None):

    try:
        if type(content) is not dict:
            content = json.loads(content)

        if constants.KEY_IV in content:
            #print ("DIFFIE HELMAN")
            dh = DiffieHellman(priv_key)
            unsigned_content = dh.decrypt(origin_pub_key, base64.b64decode(content[constants.KEY_SIGNED_CONTENT]), base64.b64decode(content[constants.KEY_IV]))
            response = json.loads(unsigned_content)
            response = response[constants.KEY_UNSIGNED_DATA]

        elif constants.KEY_SIGNED_CONTENT in content:

            signed_content = base64.b64decode(content[constants.KEY_SIGNED_CONTENT])
            unsigned_content = base64.b64decode(content[constants.KEY_UNSIGNED_CONTENT])

            pub_key.verify(signed_content, unsigned_content, ec.ECDSA(hashes.SHA256()))     

            response = json.loads(unsigned_content)

            if constants.KEY_CERTIFICATE in response:
                certificate = base64.b64decode(response[constants.KEY_CERTIFICATE])
                signed_data = base64.b64decode(response[constants.KEY_SIGNED_DATA])
                cc_certificate = x509.load_der_x509_certificate(certificate, default_backend())
                unsigned = bytes( json.dumps(response[constants.KEY_UNSIGNED_DATA],sort_keys=True) , 'utf-8')
                    
                try :
                    '''
                    cc = CC()
                    cc_store_context = cc.cc_store()
                    cert_string='-----BEGIN CERTIFICATE-----\n'+str((certificate))+'\n-----END CERTIFICATE-----'
                    #print('OK so far\n',cert_string,'\n')
                    certx509 = x509.load_der_x509_certificate(certificate, default_backend())
                    X509StoreContext(cc_store_context , certx509).verify_certificate()
                    '''                    
                    cc_certificate.public_key().verify ( signed_data ,unsigned, padding.PKCS1v15() , hashes.SHA1()  )
                    print ('Citizen Card Verification succeeded' )

                except Exception:
                    print("Exception in user code:")
                    print("-"*60)
                    traceback.print_exc(file=sys.stdout)
                    print("-"*60)
                    sys.exit(0)
            

            #Get the unsigned data 
            response = response[constants.KEY_UNSIGNED_DATA]
        
        else:
            response = content

    
        printMessage("RECEIVED CONTENT  |  " + response[constants.KEY_ACTION])

        return response
    
    except Exception:
        print("Exception in user code:")
        print("-"*60)
        traceback.print_exc(file=sys.stdout)
        print("-"*60)
        sys.exit(0)
    
    return None

def printMessage(message):
    print(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + "  |  " + message)