import constants
import random
from cryptography.hazmat.primitives import serialization

class User:

    def __init__(self, thread):
        self.id = thread                # ID da thread criada
        self.status = 1
        self.hand = []
        self.cipherTable = {}           # Hash Table
        self.username = None
        self.signature = None
        self.pub_key = None
        self.pub_key_bytes = None
        self.commands = []              # Server Commands
        self.userCommands = []          # User Commands

    def setUserName(self, username):
        self.username = username

    def setSignature(self, signature):
        self.signature = signature

    def setPublicKey(self, pub_key):
        self.pub_key = pub_key
        self.pub_key_bytes = self.pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)

    def setPublicKeyBytes(self, pub_key_bytes):
        self.pub_key_bytes = pub_key_bytes

    def getCommands(self):
        return self.commands
    
    def getUserCommands(self):
        return self.userCommands

    def getUserName(self):
        return self.username

    def getPublicKey(self):
        return self.pub_key
    
    def getPublicKeyBytes(self):
        return self.pub_key_bytes.decode("utf8").replace("'",'"')

    def getId(self):
        return self.id  
    
    def __str__(self):
        return self.username + "-" + self.signature

class Table:
    
    # Deck of cards
    deck = ['2C','3C','4C','5C','6C','7C','8C','9C','TC','JC','QC','KC','AC','2D','3D','4D','5D',
            '6D','7D','8D','9D','TD','JD','QD','KD','AD','2S','3S','4S','5S','6S','7S','8S','9S','TS',
            'JS','QS','KS','AS','2H','3H','4H','5H','6H','7H','8H','9H','TH','JH','QH','KH','AH']

    def __init__(self, id):
        self.id = id
        self.users = []                                   # Identifies all the users in the table
        self.ack_public_keys = [0,0,0,0]                  # Identifies if the users have sent an ACK about receiving the public keys
        self.status = constants.TABLE_STATUS_OPEN         # Identifies the status of the table (can be open, start game, end game)
        self.sessions = []                                # This will save the client sessions 

    def isFull(self):
        return len(self.users) == constants.TABLE_NUMBER_OF_PLAYERS

    # We are going to identify the user by his index
    def getUserIndex(self, user):
        idx = 0
        for u in self.users:
            if (u == user):
                return idx
            idx +=1
        return idx
    
    # Set in the ack array that the user has sent an ACK about receiving and loading the public keys
    def setUserACK(self, user):
        idx = self.getUserIndex(user)
        self.ack_public_keys[idx]=1

    # Verify if we are able to send the deck to the players, all the ack must have been sent by the users
    def canDeckBeSent(self):
        for i in range(0,constants.TABLE_NUMBER_OF_PLAYERS-1):
            if (self.ack_public_keys[i]==0):
                return False

        return True

    # Returns if the user is in this table
    def isUserInTable(self, user):
        return (user in self.users)


    def startGame(self):
        self.status = constants.TABLE_STATUS_GAME_START

    def getRandomUser(self):
        idx = random.randint(0,constants.TABLE_NUMBER_OF_PLAYERS-1)
        return self.users[idx], idx

    def getShuffledDeck(self):
        #return random.shuffle(self.deck)
        return self.deck

    def getId(self):
        return self.id

    def getStatus(self):
        return self.status


    def join(self, user):
        if user not in self.users:
            self.users.append(user)

    def leave(self, user):
        if user in self.users:
            self.users.remove(user)



    def getUser(self, idx):
        return self.users[idx]
    
    def getUsers(self):
        return self.users