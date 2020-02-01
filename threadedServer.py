'''
kill processes
sudo lsof -t -i tcp:3000 | xargs kill -9
'''

import socket
import threading
import inspect
import json
import time
import random
import string
import sys
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
        self.priv_key, self.pub_key = create_ecdhe_keys()

        #This is the public key (as a byte array) that all the users will request after signing in
        self.pem_pub = self.pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

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
                    if (constants.DEBUG_MODE):
                        printMessage ("Server Command will be executed ... ") 
                    msg = user.getCommands().pop(0)
                    client.send(sendContent(msg, self.priv_key, None, True, None))
                
                # User Commands
                if (len(user.getUserCommands()) > 0):
                    if (constants.DEBUG_MODE):
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
            encrypt = True
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
                clientAction = receiveContent(action, user.getPublicKey())     
                if (clientAction[constants.KEY_ACTION] == constants.LOGIN):
                    op = 1
                
                if (clientAction[constants.KEY_ACTION] == constants.EXCHANGE_PUBLIC_KEYS):
                    encrypt = False
                    op = 2

                if (clientAction[constants.KEY_ACTION] == constants.JOIN_TABLE):
                    op = 10

                if (clientAction[constants.KEY_ACTION] == constants.ACK_PUBLIC_KEYS):
                    op = 3
                
                if (clientAction[constants.KEY_ACTION] == constants.DECK_SHUFFLED):
                    op = 4

                if (clientAction[constants.KEY_ACTION] == constants.DECK_DISTRIBUTED):
                    op = 5

                if (clientAction[constants.KEY_ACTION] == constants.ACK_BIT_COMMITMENT):
                    op = 6
                
                if (clientAction[constants.KEY_ACTION] == constants.ACK_DECK_CYPHER_KEY):
                    op = 7
                
                if (clientAction[constants.KEY_ACTION] == constants.ACK_DECRYPT_HAND):
                    op = 8
                
                if (clientAction[constants.KEY_ACTION] == constants.CARD_PLAYED):
                    op = 9
            
                if (clientAction[constants.KEY_ACTION] == constants.HAND_UPDATED):
                    op = 11
            
                if (clientAction[constants.KEY_ACTION] == constants.COMPLAIN):
                    op = 12

                if (clientAction[constants.KEY_ACTION] == constants.ACK_COMPLAIN):
                    op = 13

                functions = {                    
                    '1' : self.login,                        # The login will save the user info and assign a table to the user
                    '2' : self.exchangePublicKeys,           # Exchange the public keys 
                    '3' : self.ackPublicKeys,                # The users are notifying the server that they received the keys
                    '4' : self.deckShuffled,                 # The deck was shuffled by all the players
                    '5' : self.deckDistributed,              # The deck was distributed among all players 
                    '6' : self.ackBitCommitment,             # The users are notifying the server that they did the bit commitment
                    '7' : self.ackDeckCypherKey,             # The users are notifying the server that they have shared the keys to decypher the hand
                    '8' : self.ackDecryptHand,               # The users are notifying the server that they decrypted their hand
                    '9' : self.cardPlayed,
                    '10' : self.joinTable,
                    '11' : self.handUpdated,
                    '12' : self.complain, 
                    '13' : self.ackComplain
                }

                response = functions.get(str(op))(user, clientAction)

            return sendContent(response, self.priv_key, None, encrypt, None)

    #Here the deck was already shuffled and encrypted by all the players
    #Now we have to select a random player to start distributing the cards
    def deckShuffled(self, user, action):
        table = self.getUserTable(user)
        user, idx  = table.getRandomUser()
        printMessage("Server selected user " +  user.getUserName() + " to start card distribution| " + str(idx))
    
        command = { constants.KEY_ACTION                 : constants.DECK_DISTRIBUTION,
                    constants.KEY_DECK                   : action[constants.KEY_DECK],
                    constants.KEY_DECK_COUNT             : 52,
                    constants.KEY_PLAYER_IDX             : idx,
        }   

        user.getCommands().append(command)

        command = {constants.KEY_ACTION : constants.WAIT}
        return command

    def complain(self, user, action):
        table = self.getUserTable(user)
        for u in table.getUsers():
            table.setUserACKComplain(user, action[constants.KEY_R_TWO], base64.b64decode(action[constants.KEY_CIPHERED_HAND]))

            if (u != user):
                command = { constants.KEY_ACTION            : constants.COMPLAIN_SENT, 
                            constants.KEY_R_TWO             : action[constants.KEY_R_TWO],
                            constants.KEY_CIPHERED_HAND     : action[constants.KEY_CIPHERED_HAND],
                            constants.KEY_PLAYER_IDX        : table.getUserIndex(user)
                }
                u.getCommands().append(command)
        
        command = {constants.KEY_ACTION : constants.WAIT}
        return command

    def exchangePublicKeys(self, user, action):    
        # Save and load the User public key   
        try:
            user.setPublicKey(serialization.load_pem_public_key(bytes(action[constants.KEY_CLIENT_PUBLIC_KEY],"utf8"), default_backend()))

            # Generate a new command to send the server public key
            command = {}
            command[constants.KEY_ACTION] =  constants.EXCHANGE_PUBLIC_KEYS
            command[constants.KEY_PUB_CERT] = self.pem_pub.decode("utf8").replace("'",'"') 
            return command
        except Exception:
            print("Exception in user code:")
            print("-"*60)
            traceback.print_exc(file=sys.stdout)
            print("-"*60)
            sys.exit(0)
        return None

    def login(self, user, action):

        user.setUserName(action[constants.KEY_USERNAME])   
        user.setIdentification(action[constants.KEY_IDENTIFICATION])    
        user.setPublicKey(serialization.load_pem_public_key(bytes(action[constants.KEY_CLIENT_PUBLIC_KEY],"utf8"), default_backend()))

        # Join the user the croupier (we only have one croupier)
        printMessage("Linked to Server : " + user.getUserName() + " - " + str(user.getIdentification()))
        self.joinToCroupier(user) 

        arr = []
        for u in self.users:
            arr.append(u.getUserName())

        command = {constants.KEY_ACTION : constants.ASK_JOIN_TABLE, constants.KEY_PLAYERS: arr}

        return command

    def joinTable(self, user, action):  

        if (action[constants.KEY_JOIN_TABLE]):

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
        else:
            self.removeFromCroupier(user)

        command = {constants.KEY_ACTION : constants.WAIT}

        return command

    def handUpdated(self, user, action):
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
    
    def ackComplain(self, user, action): 
        printMessage("ACK from user " +  user.getUserName())
        table = self.getUserTable(user)
        
        table.setUserACKComplain(user, action[constants.KEY_R_TWO], base64.b64decode(action[constants.KEY_CIPHERED_HAND]))
        
        if (table.canExecuteComplain()):

            try:
                #print ('CHECK HERE')
                hands = table.getComplainHands()
                for i in range(4):
                    table.setComplainDecryptedHands(self._decrypt_hand(eval(hands[i]),table.getCypherKeysArray()),i)    

                table.verifyComplain()
            except Exception:
                print("Exception in user code:")
                print("-"*60)
                traceback.print_exc(file=sys.stdout)
                print("-"*60)
                sys.exit(0)
            

        command = {constants.KEY_ACTION : constants.WAIT}

        return command

    def sendDeckToRandomPlayer(self, table):
            user, idx  = table.getRandomUser()
            table.setUserStartIdx (idx)
            printMessage("Server selected user " +  user.getUserName() + " | " + str(idx))

            command = {constants.KEY_ACTION                 : constants.SHUFFLE_DECK,
                       constants.KEY_DECK                   : table.getShuffledDeck(),
                       constants.KEY_PLAYER_IDX             : idx,
            }   

            user.getCommands().append(command)

    def deckDistributed(self, user, action):

        printMessage ("The Deck was distributed by all players")
        table = self.getUserTable(user)
   
        for u in table.getUsers():
            command = { constants.KEY_ACTION                 : constants.BIT_COMMITMENT }
            u.getCommands().append(command)

        # Deck already distributed
        command = {constants.KEY_ACTION : constants.WAIT}
        return command

    def ackBitCommitment(self, user, action): 
        printMessage("ACK Bit Commitment from user " +  user.getUserName())
        table = self.getUserTable(user)

        bit_commitment = action[constants.KEY_BIT_COMMITMENT]
        bit_commitment_r_one = action[constants.KEY_R_ONE]
        
        table.setUserACKBitCommitment(user,bit_commitment,bit_commitment_r_one )

        if (table.canDeckBeDecrypted()):
            printMessage ("All the bit commitments where done!!!")
            for u in table.getUsers():
                command = { constants.KEY_ACTION                 : constants.SHARE_CARDS_CYPHER_KEY,
                            constants.KEY_BIT_COMMITMENT         : table.getBitCommitments(),    
                            constants.KEY_R_ONE                  : table.getBitCommitmentsROnes()   
                        }
                
                u.getCommands().append(command)

        command = {constants.KEY_ACTION : constants.WAIT}

        return command

    def ackDeckCypherKey(self, user, action): 
        printMessage("ACK Deck Cypher Key  from user " +  user.getUserName())
        table = self.getUserTable(user)
        
        table.setCypherKey(user,action[constants.KEY_DECK_CYPHER])
        table.setUserACKDeckCypherKey(user)

        if (table.canDeckCypherKeysBeShared()):

            command = {constants.KEY_ACTION         : constants.DECRYPT_HAND,
                       constants.KEY_CYPHER_ARRAY   : table.getCypherKeysArray()}

            for u in table.getUsers():
                u.getCommands().append(command)

            printMessage ("All the keys where shared!!!")


        command = {constants.KEY_ACTION : constants.WAIT}

        return command

    def ackDecryptHand(self, user, action):
        printMessage("ACK Decrypt Hand from user " +  user.getUserName())
        table = self.getUserTable(user)
        
        table.setUserACKDecryptHand(user)
        if (action[constants.KEY_START_PLAYER] == '1'):
            table.setCurrentHandStartPlayerIdx(table.getUserIndex(user))
            table.setUserStartGameIdx(table.getUserIndex(user))

        if (table.canStartGame()):
            printMessage ("All the hands where decrypted!!!")
            
            u = table.getUser(table.getCurrentHandStartPlayerIdx())

            command = {constants.KEY_ACTION             : constants.PLAY_CARD, 
                       constants.KEY_PLAY_CURRENT_HAND  : table.getCurrentHand(), 
                       constants.KEY_PLAY_FIRST_PLAYER  : table.getCurrentHandStartPlayerIdx()}

            u.getCommands().append(command)
                     

        command = {constants.KEY_ACTION : constants.WAIT}

        return command

    def cardPlayed(self, user, action):
        table = self.getUserTable(user)
        idx = table.getUserIndex(user)
        card = action[constants.KEY_PLAY_CARD] 

        hand_to_print = table.getCurrentHand()
        hand_to_print[idx] = card    

        nextPlayer = table.playHand(card, idx)

        if (len(table.getHistory()) != 13):
            command = {constants.KEY_ACTION             : constants.UPDATE_CURRENT_HAND,
                       constants.KEY_PLAY_CURRENT_HAND  : hand_to_print}

            for us in table.getUsers():
                    us.getCommands().append(command)

            # get the next player to play
            u = table.getUser(nextPlayer)
            command = {constants.KEY_ACTION             : constants.PLAY_CARD, 
                       constants.KEY_PLAY_CURRENT_HAND  : table.getCurrentHand(), 
                       constants.KEY_PLAY_FIRST_PLAYER  : table.getCurrentHandStartPlayerIdx()}

            u.getCommands().append(command)

        else:
            print ("Game Over!!")
            table.printHistory()    
            for u in table.getUsers():
                command = { constants.KEY_ACTION        : constants.GAME_OVER, 
                            constants.KEY_HISTORY       : table.getHistory(), 
                            constants.KEY_HISTORY_POINTS: table.getHistoryPoints()
                            }
                u.getCommands().append(command)

        command = {constants.KEY_ACTION : constants.WAIT}

        return command

    ########################## DATA FUNCTIONS ##########################

    def _decrypt_hand(self, hand, deck_keys):
        new_hand = hand
        for i in range(4):
            symm_key = create_symm_key(deck_keys[i])
            for j in range(constants.CARDS_IN_HAND):
                card = new_hand[j]
                if (i == 0):  
                    card = base64.b64decode(hand[j])    
                
                if(constants.USE_AESCBC):
                    new_hand[j] = decipher_with_symm_key_AESCBC(symm_key, card)
                if(constants.USE_AESOFB):
                    new_hand[j] = decipher_with_symm_key_AESOFB(symm_key, card)
                if(constants.USE_AESCFB):
                    new_hand[j] = decipher_with_symm_key_AESCFB(symm_key, card)

        for i in range(constants.CARDS_IN_HAND):
            new_hand[i] = new_hand[i].decode().strip()

        return new_hand

    # This will join the user to the croupier 
    def joinToCroupier(self, user):
        if user not in self.users:
            self.users.append(user)
    
    def removeFromCroupier(self, user):
        if user not in self.users:
            self.users.remove(user)

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

    if 'DEBUG' in sys.argv:
        constants.DEGUG_MODE = True

    if 'DECK' in sys.argv:
        constants.RANDOM_CARD_DISTRIBUTION = True

    ThreadedServer('',constants.SERVER_PORT).listen()