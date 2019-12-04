'''
kill processes
sudo lsof -t -i tcp:3000 | xargs kill -9
'''

import socket
import threading
import json
import random
import string
import constants
from game import *
from common import *
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptos import *

keys = {}

class ThreadedServer(object):

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket()
        self.sock.bind((self.host, self.port))
        self.users = []                             # Save in the server all the users that have connected to the server
        self.tables = []                            # Save all the tables that where created 
         
        #The server will generate a set of keys (private and public)
        self.priv_key, self.pub_key = create_asymmetric_keys()

        #This is the public key (as a byte array) that all the users will request after signing in
        self.pem_pub = self.pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)


    # Create a different thread for each client that joins 
    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(constants.SOCKET_TIMEOUT)       
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        user = User(threading.get_ident()) 
        timeIDLE = 0
        while True:
            
            try:
                # Server Commands
                if (len(user.getCommands()) > 0):
                    printMessage ("Server Command will be executed ... ") 
                    msg = user.getCommands().pop(0)
                    client.send(sendContent(msg, user.getPublicKey(), None, True))
                
                # User Commands
                if (len(user.getUserCommands()) > 0):
                    printMessage ("User Command will be executed ... ")  
                    msg = user.getUserCommands().pop(0)
                    msg = json.dumps(msg).encode()
                    client.send(msg)

                #socket connection
                data = client.recv(constants.BUFFER_SIZE_SERVER)    
                if data:  
                    timeIDLE = 0
                    client.send(self.executeClientAction(user,data.decode()))

            except socket.timeout:
                timeIDLE+= constants.SOCKET_TIMEOUT
                if (timeIDLE >= constants.SOCKET_IDLE_LIMIT ):
                    client.close()
                    return False
            except:
                client.close()
                return False
    
    def executeClientAction(self, user, action):
            
            #Use the load to pick up the action and convert it to a dict/json
            if type(action) is not dict:
                content = json.loads(action)            
            
            if (constants.KEY_CIPHERED_PLAYER_IDX in action and content[constants.KEY_CIPHERED_PLAYER_IDX] != -1):
                # This message is not for the server / croupier, the server will simply redirect it 
                # also the server is not able to decrypt it since the message is encrypted with the public key 
                # of the destination user/player 
                table = self.getUserTable(user)
                destinationUser = table.getUser(content[constants.KEY_CIPHERED_PLAYER_IDX])
                destinationUser.getUserCommands().append(content)

                response = {constants.KEY_ACTION : constants.WAIT}
            
            else:
                op = -1 
                clientAction = receiveContent(action, self.priv_key)     
                if (clientAction[constants.KEY_ACTION] == constants.LOGIN):
                    op = 1
                
                if (clientAction[constants.KEY_ACTION] == constants.EXCHANGE_PUBLIC_KEYS):
                    op = 2

                if (clientAction[constants.KEY_ACTION] == constants.ACK_PUBLIC_KEYS):
                    op = 3
                
                if (clientAction[constants.KEY_ACTION] == constants.DECK_SHUFFLED):
                    op = 4

                functions = {                    
                    '1' : self.login,                        # The login will save the user info and assign a table to the user
                    '2' : self.exchangePublicKeys,           # Exchange the public keys 
                    '3' : self.ackPublicKeys,                # The users are notifying the server that they received the keys
                    '4' : self.deckShuffled,                 # The deck was shuffled by all the players

                }


                response = functions.get(str(op))(user, clientAction)

            return sendContent(response, user.getPublicKey(), None, True)

    def deckShuffled(self, user, action):
        print(action[constants.KEY_DECK])  
        command = {constants.KEY_ACTION : constants.WAIT}
        return command

    def exchangePublicKeys(self, user, action):    
        # Save and load the User public key     
        user.setPublicKey(serialization.load_pem_public_key(action[constants.KEY_CLIENT_PUBLIC_KEY].encode('ascii'), default_backend()))

        # Generate a new command to send the server public key
        command = {}
        command[constants.KEY_ACTION] =  constants.EXCHANGE_PUBLIC_KEYS
        command[constants.KEY_PUB_CERT] = self.pem_pub.decode("utf8").replace("'",'"') 
        return command

    def login(self, user, action):
        user.setUserName(action[constants.KEY_USERNAME])   
        user.setSignature(action[constants.KEY_CITIZEN_CARD_INFO])    

        # Join the user the croupier (we only have one croupier)
        printMessage("Linked to Server : " + user.getUserName())
        self.joinToCroupier(user)     

        # Check if there is a table where we can join the user and if not let's create one
        table = self.assignTable(user)

        #Check if the table is full to see if we are able to start the game 
        if table.isFull():
            printMessage("The table is full!")
            
            for u in table.getUsers():
                command = { constants.KEY_ACTION                 : constants.SHARE_PUB_KEYS,
                            constants.KEY_PUB_KEY_IDX_0          : table.getUser(0).getPublicKeyBytes(),
                            constants.KEY_PUB_KEY_IDX_1          : table.getUser(1).getPublicKeyBytes(),
                            constants.KEY_PUB_KEY_IDX_2          : table.getUser(2).getPublicKeyBytes(),
                            constants.KEY_PUB_KEY_IDX_3          : table.getUser(3).getPublicKeyBytes(),
                }

                u.getCommands().append(command)

        command = {constants.KEY_ACTION : constants.WAIT}

        return command

    def ackPublicKeys(self, user, action): 
        printMessage("ACK from user " +  user.getUserName())
        table = self.getUserTable(user)
        table.setUserACK(user)

        if (table.canDeckBeSent()):
            self.sendDeckToRandomPlayer(table)
        
        command = {constants.KEY_ACTION : constants.WAIT}
        
        return command
    
    def sendDeckToRandomPlayer(self, table):
            user, idx  = table.getRandomUser()
            printMessage("Server selected user " +  user.getUserName() + " | " + str(idx))

            command = {constants.KEY_ACTION                 : constants.SHUFFLE_DECK,
                       constants.KEY_DECK                   : table.getShuffledDeck(),
                       constants.KEY_PLAYER_IDX             : idx,
            }   

            user.getCommands().append(command)

    #################################### DATA FUNCTIONS ##########################

    # This will join the user to the croupier 
    def joinToCroupier(self, user):
        if user not in self.users:
            self.users.append(user)

    # This will assign a Table to the user, it will create one if it doesn't exist or if all are full
    def assignTable(self, user):
        if (len(self.tables) == 0 ):
            table = self.createTable()
            table.join(user)
        else:
            joined = False
            for t in self.tables:
                if not t.isFull():
                    joined = True 
                    t.join(user)
                    table = t
            
            if not joined:
                table = self.createTable()
                table.join(user)
        
        return table

    # This will just create a new table and save it 
    def createTable(self):
        table = Table(len(self.tables)+1)
        self.tables.append(table)
        return table

    # This function will retrieve the table that was assigned to the user
    def getUserTable(self, user):
        for t in self.tables:
            if t.isUserInTable(user):
                return t
        return None 


if __name__ == "__main__":
    ThreadedServer('',constants.SERVER_PORT).listen()