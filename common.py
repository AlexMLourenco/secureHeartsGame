import constants
import base64
import json
from cryptos import *
from datetime import datetime

def encodeContent (content):
    return json.dumps(content).encode()

def sendContent( content, pub_key, sessionKey=None, encrypt=True, sessionUserIdx=-1): 
    
    printMessage("SENDING CONTENT  |  " + content[constants.KEY_ACTION])  
    if encrypt:

        # Let's create a symetric key to encrypt the content that we are about to send 
        symm_key = create_symm_key(randomSecret())

        # Make a json of the content          
        s = json.dumps(content).encode('utf-8')

        #O conteudo a cifrar tem de ser multiplo de 16 senao a cifra nao funciona
        if (len(s) % 16 != 0):
            block = int(len(s)/16)
            block = (block + 1) * 16
            s = s.ljust(block)
        else:
            block = 0       
        
        # Cifrar o conteudo do commando a chave simétrica
        ciphered_content = cipher_with_symm_key(symm_key, s)

        if (sessionKey == None):
            # Cifrar a nossa chave com a chave publica do servidor (para o croupier poder desencriptar)
            ciphered_symm_key = cipher_asymmetric_key(pub_key, symm_key)
        else:
            # Cifrar com a chave publica do cliente de destino (ver como obter a chave publica do cliente)
            ciphered_symm_key = cipher_asymmetric_key(sessionKey, symm_key)

        #Criar o commando a enviar ao servidor 
        command = { constants.KEY_CIPHERED_CONTENT          : base64.b64encode(ciphered_content).decode("utf8").replace("'",'"'),
                    constants.KEY_CIPHERED_KEY              : base64.b64encode(ciphered_symm_key).decode("utf8").replace("'",'"'),  
                    constants.KEY_CIPHERED_PLAYER_IDX       : sessionUserIdx
        }

        content = command
    else:
        pass

       
    #Passar o objeto de python para json 
    command = json.dumps(content).encode()
    return command

def receiveContent(content, priv_key):
    
    if type(content) is not dict:
        content = json.loads(content)

    if constants.KEY_CIPHERED_CONTENT in content:

        action = base64.b64decode(content[constants.KEY_CIPHERED_CONTENT])
        key = base64.b64decode(content[constants.KEY_CIPHERED_KEY])

        # Let's decipher the key that user has sent, using our private key 
        # because all the content was encrypted with the public key 
        generated_key = decipher_asymmetric_key(priv_key, key)

        # Now that we have the key we can decipher the content with it 
        final_content = decipher_with_symm_key(generated_key, action)

        #Finally load the content as JSON
        response = json.loads(final_content)
    else:

        response = content

    printMessage("RECEIVED CONTENT  |  " + response[constants.KEY_ACTION])

    return response

def printMessage(message):
    print(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + "  |  " + message)