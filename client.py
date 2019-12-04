import socket 
import json
import threading
import random
from getpass import getpass
import constants
from cryptos import * 
from common import *
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class Client:

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.tcpClient = socket.socket() 
        self.tcpClient.connect((host, port))

        # When the game starts we will save all the players public keys
        self.shared_public_keys = []

        # The client must create a set of private and public keys to allow the communication with other players
        self.priv_key, self.pub_key = create_asymmetric_keys()

         # This will be the client public key (stored as bytes) so that it can be sent and shared with others
        self.pem_pub = self.pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)

        # This is the public key that will allow the communication with the croupier (server)
        self.server_pub_key = None
        self.exchangePublicKeys()

        # This method will require the citizen card to login 
        self.sign_in()

        self.serverClientId = -1


        ####### Variables to manage the game state  ######
        self.deck                   = {}        # Hash Map for Cipher
        self.deck_shuffled          = False     # Tells if the deck was already shuffled
        self.card_cypher_secret     = None      # Saves the key that was used to create the cypher for the cards
        self.card_cypher_key        = None      # Creates a key with the card cypher secret
        
    
    # This function will send the content to the server 
    def sendToServer(self, content, sessionKey=None, encrypt=True, sessionUserIdx=-1):
        # this will create a command to send to the server or another player 
        command = sendContent(content, self.server_pub_key, sessionKey, encrypt,sessionUserIdx)

        # send the command to the server 
        self.tcpClient.sendall(command)

        # Wait for a server response    
        return self.listenToServer()
    
    # This function will wait for a server response
    def listenToServer(self):
         # Wait for a server response    
        data = self.tcpClient.recv(constants.BUFFER_SIZE_CLIENT)

        #Converter para JSON 
        response = receiveContent(data, self.priv_key)

        return response

    #DONE: This function will ask for the server public key and also send the user public key 
    def exchangePublicKeys(self):
        command = { constants.KEY_ACTION : constants.EXCHANGE_PUBLIC_KEYS,
                    constants.KEY_CLIENT_PUBLIC_KEY: self.pem_pub.decode("utf8").replace("'",'"')}

        #Enviar o comando ao servidor
        response = self.sendToServer(command, None, False,-1)
        
        self.server_pub_key = serialization.load_pem_public_key(response[constants.KEY_PUB_CERT].encode('ascii'), default_backend())

    #DONE: This function will send the user citizen card info and wait for the game to start 
    def sign_in(self):
        #TODO: repor e apagar o randomUserName()
        #O user autentica com o cartão de cidadão
        #data = login()
        data = {}
        data['username'] = randomUserName()
        data['signature'] = randomSecret()

        command = { constants.KEY_ACTION : constants.LOGIN,
                    constants.KEY_USERNAME  : data['username'],
                    constants.KEY_CITIZEN_CARD_INFO  : str(data['signature'])
        }

        response = self.sendToServer(command, None, True,-1)

        if (response[constants.KEY_ACTION] == constants.WAIT):
            printMessage ("Waiting for Server ....")
    
    def listen(self):
        while True:
           
            response = self.listenToServer()

            sessionKey     = None
            sessionUserIdx = -1
            command        = None

            if (response[constants.KEY_ACTION] == constants.SHARE_PUB_KEYS):
                command = self.savePlayersPublicKeys(response)
            
            if (response[constants.KEY_ACTION] == constants.SHUFFLE_DECK or response[constants.KEY_ACTION] == constants.SEND_DECK_TO_NEXT_PLAYER):
                if (not self.deck_shuffled):
                    command, sessionUserIdx = self.shuffleDeck(response)
                    sessionKey = self.shared_public_keys[sessionUserIdx]
                    print (response[constants.KEY_DECK])
                else:
                    command = {constants.KEY_ACTION :   constants.DECK_SHUFFLED,
                               constants.KEY_DECK   :   response[constants.KEY_DECK] 
                    }
                    printMessage("The Deck was shuffled by all the players ...")

            response = self.sendToServer(command, sessionKey, True, sessionUserIdx) 
            
            if (response[constants.KEY_ACTION] == constants.WAIT):
                printMessage("Waiting for Server ....")
        

    # DONE This function will save all the players public keys so that if we need to send a message to them 
    #      we can encrypt it with their public key
    def savePlayersPublicKeys(self, response):

        self.shared_public_keys = []
        self.shared_public_keys.append(serialization.load_pem_public_key(response[constants.KEY_PUB_KEY_IDX_0].encode('ascii'), default_backend()))
        self.shared_public_keys.append(serialization.load_pem_public_key(response[constants.KEY_PUB_KEY_IDX_1].encode('ascii'), default_backend()))
        self.shared_public_keys.append(serialization.load_pem_public_key(response[constants.KEY_PUB_KEY_IDX_2].encode('ascii'), default_backend()))
        self.shared_public_keys.append(serialization.load_pem_public_key(response[constants.KEY_PUB_KEY_IDX_3].encode('ascii'), default_backend()))
        
        printMessage("Players Public Keys LOADED!")

        command = { constants.KEY_ACTION :      constants.ACK_PUBLIC_KEYS}

        return command

    # This will aplly a cipher to the card on the deck
    def cipherCard(self,card):
        # cipher the cards
        return card

    # This will shuffle the deck and send it to the next player
    def shuffleDeck(self, command):
        temp = command[constants.KEY_DECK]
        random.shuffle(temp)
        self.card_cypher_secret = randomSecret()
        self.card_cypher_key = create_symm_key(self.card_cypher_secret)
        arr = []
        for t in temp:   
            self.deck[t] = self.cipherCard(t)
            arr.append(self.deck[t])
        
        idx = command[constants.KEY_PLAYER_IDX]
        idx = 0 if idx == 3 else idx + 1

        command = { constants.KEY_ACTION            : constants.SEND_DECK_TO_NEXT_PLAYER,
                    constants.KEY_DECK              : arr,
                    constants.KEY_PLAYER_IDX        : idx
        }
        
        self.deck_shuffled = True
        return command, idx
    
client = Client(socket.gethostname() ,constants.SERVER_PORT)
client.listen()