import socket 
import json
import threading
import random
import sys
from getpass import getpass
import constants
from cryptos import * 
from common import *
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import pickle

class Client:

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.tcpClient = socket.socket() 
        self.tcpClient.connect((host, port))

        # When the game starts we will save all the players public keys
        self.shared_public_keys = []
        # This is the public key that will allow the communication with the croupier (server)
        self.server_pub_key = None
        #This will store the citizen card session
        self.cc = None

        # The client must create a set of private and public keys to allow the communication with other players and the server 
        self.priv_key, self.pub_key = create_ecdhe_keys()

        # This will be the client public key (stored as bytes) so that it can be sent and shared with others
        self.pem_pub = self.pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

        self.exchangePublicKeys()

        # Here we will check for the use of the citizen card 
        if constants.USE_CC:
            self.cc = CC()
     
        self.certificateSignature   = None      # Will save the signature from the citizen card for later encryption
        
        # This method will require the citizen card to login 
        self.sign_in()
        self.serverClientId = -1

        ####### Variables to manage the game state  ######
        self.deck                               = {}        # Hash Map for Cipher
        self.deck_shuffled                      = False     # Tells if the deck was already shuffled
        self.deck_empty                         = False     # Tells if the deck is empty
        self.card_cypher_secret                 = None      # Saves the key that was used to create the cypher for the cards
        self.card_cypher_key                    = None      # Creates a key with the card cypher secret
        self.hand                               = []        # Hand of the player
        self.hand_played_cards                  = []        # Cards already played by the user    
        self.cyphered_hand                      = None      # Hand cyphered 
        self.bit_commitment                     = None      # Hex value of the bit commitment
        self.bit_commitment_r_one               = None      # R one used to create bit commitment
        self.bit_commitment_r_two               = None      # R two used to create bit commitment
        self.deck_keys                          = None      # Saves the keys that where used to encrypt the deck
        self.players_bit_commitments            = None      # Saves the bit commitments of all the players
        self.players_bit_commitments_r_ones     = None      # Saves the bit commitments r-one of all the players

        self.menu_game()    # History or Game ?

    # This function will send the content to the server 
    def sendToServer(self, content, sessionKey=None, encrypt=True, sessionUserIdx=-1, signed = False, sessionOriginUserIdx = -1):
        cc = None
        if (signed):
            cc = self.cc
        # this will create a command to send to the server or another player 
        command = sendContent(content, self.priv_key, sessionKey, encrypt,sessionUserIdx,cc,sessionOriginUserIdx)
        # send the command to the server 
        self.tcpClient.sendall(command)

        # Wait for a server response    
        return self.listenToServer()
    
    # This function will wait for a server response
    def listenToServer(self):
         # Wait for a server response    
        data = self.tcpClient.recv(constants.BUFFER_SIZE_CLIENT)

        #Converter para JSON 
        if type(data) is not dict:
            data = json.loads(data)
        
        originPubliKey = None
        if constants.KEY_SESSION_ORIGIN_IDX in data:
            originPubliKey = self.shared_public_keys[int(data[constants.KEY_SESSION_ORIGIN_IDX])] 

        response = receiveContent(data, self.server_pub_key, self.priv_key, originPubliKey)

        return response

    def listen(self):
        while True:
           
            response = self.listenToServer()

            sessionKey                  = None
            sessionUserIdx              = -1
            sessionOriginUserIdx        = -1
            command                     = None

            if (response[constants.KEY_ACTION] == constants.SHARE_PUB_KEYS):
                command = self.savePlayersPublicKeys(response)

            if (response[constants.KEY_ACTION] == constants.UPDATE_CURRENT_HAND):
                command = self.updateCurrentHand(response)

            
            if (response[constants.KEY_ACTION] == constants.SHUFFLE_DECK or response[constants.KEY_ACTION] == constants.SEND_DECK_TO_NEXT_PLAYER):
                if (not self.deck_shuffled):
                    command, sessionUserIdx = self.shuffleDeck(response)
                    sessionKey = self.shared_public_keys[sessionUserIdx]
                    sessionOriginUserIdx = response[constants.KEY_PLAYER_IDX]
                else:
                    command = {constants.KEY_ACTION :   constants.DECK_SHUFFLED,
                               constants.KEY_DECK   :   response[constants.KEY_DECK] 
                    }
                    printMessage("The Deck was shuffled by all the players ...")
            
            if ( response[constants.KEY_ACTION]  == constants.DECK_DISTRIBUTION):
                command, sessionUserIdx = self.deckDistribution(response)
                if (self.deck_empty):
                    sessionUserIdx = -1
                    command = {constants.KEY_ACTION :   constants.DECK_DISTRIBUTED }
                    printMessage("The Deck was distributed by all the players ...")
                else:
                    sessionOriginUserIdx = response[constants.KEY_PLAYER_IDX]
                    sessionKey = self.shared_public_keys[sessionUserIdx]
            
            if ( response[constants.KEY_ACTION]  == constants.BIT_COMMITMENT):
                command = self.doBitCommitment(response)
            
            if ( response[constants.KEY_ACTION]  == constants.SHARE_CARDS_CYPHER_KEY):
                command = self.shareCardsCypherKey(response)

            if (response[constants.KEY_ACTION] == constants.DECRYPT_HAND):
                command = self.decryptHand(response)

            if (response[constants.KEY_ACTION] == constants.PLAY_CARD):
                command = self.playCard(response)

            if (response[constants.KEY_ACTION] == constants.COMPLAIN_SENT):
                command = self.complainSent(response)
            
            if (response[constants.KEY_ACTION] == constants.GAME_OVER):
                self.gameOver(response)


            response = self.sendToServer(command, sessionKey, True, sessionUserIdx, False, sessionOriginUserIdx) 
            
            if (response[constants.KEY_ACTION] == constants.WAIT):
                printMessage("Waiting for Server ....")
        
    # STEP 1: This function will ask for the server public key and also send the user public key 
    def exchangePublicKeys(self):
        command = { constants.KEY_ACTION                    : constants.EXCHANGE_PUBLIC_KEYS,
                    constants.KEY_CLIENT_PUBLIC_KEY         : self.pem_pub.decode("utf8").replace("'",'"'),
                    constants.KEY_USE_CC                    : constants.USE_CC}

        #Enviar o comando ao servidor
        response = self.sendToServer(command, None, False,-1)

        self.server_pub_key = serialization.load_pem_public_key(response[constants.KEY_PUB_CERT].encode('ascii'), default_backend())

    # STEP 2: This function will send the user citizen card info and wait for the game to start 
    def sign_in(self):
        signed = True
        data = {}
        if constants.USE_CC:
            data['username'] = self.cc.get_name()
            data['identification'] = self.cc.get_number()
        else:
            signed = False
            data['username'] = randomUserName()
            data['identification'] = randomNumber()
        
        data['public_key'] = self.pem_pub.decode("utf8").replace("'",'"')

        command = { constants.KEY_ACTION :              constants.LOGIN,
                    constants.KEY_USERNAME  :           data['username'],
                    constants.KEY_IDENTIFICATION:       data['identification'],
                    constants.KEY_CLIENT_PUBLIC_KEY :   data['public_key'] 
        }

        response = self.sendToServer(command, None, True,-1, signed)

        if (response[constants.KEY_ACTION] == constants.ASK_JOIN_TABLE):
            self.ask_join_table(response[constants.KEY_PLAYERS])
    
    # STEP 3: This function will ask the user if he wants to join a table
    def ask_join_table(self, players): 
         
        join = True
        if not constants.DEBUG_MODE :
            while True:
                try:
                    print(players)    
                    option = str(input("Do you to join this table? (y/n) "))
                except ValueError:
                    print("Sorry, Select a valid option")
                    continue
                else:
                    
                    if option == "y" or option == "n":
                        break
                    print("Sorry, Select a valid option")
                    continue
            if ( option == "n"):
                join = False

        command = { constants.KEY_ACTION : constants.JOIN_TABLE,
                    constants.KEY_JOIN_TABLE  : join
        }
        
        response = self.sendToServer(command, None, True,-1)

        if (not join):
            sys.exit(0)

        if (response[constants.KEY_ACTION] == constants.WAIT):
            printMessage("Waitting for server ...")
        
    # STEP 4 This function will save all the players public keys so that if we need to send a message to them 
    # we can encrypt it with their public key
    def savePlayersPublicKeys(self, response):

        self.shared_public_keys = []
        self.shared_public_keys.append(serialization.load_pem_public_key(response[constants.KEY_PUB_KEY_IDX_0].encode('ascii'), default_backend()))
        self.shared_public_keys.append(serialization.load_pem_public_key(response[constants.KEY_PUB_KEY_IDX_1].encode('ascii'), default_backend()))
        self.shared_public_keys.append(serialization.load_pem_public_key(response[constants.KEY_PUB_KEY_IDX_2].encode('ascii'), default_backend()))
        self.shared_public_keys.append(serialization.load_pem_public_key(response[constants.KEY_PUB_KEY_IDX_3].encode('ascii'), default_backend()))
        
        printMessage("Players Public Keys LOADED!")

        command = { constants.KEY_ACTION :      constants.ACK_PUBLIC_KEYS}

        return command
    
    def updateCurrentHand(self, response):
        current_hand = response[constants.KEY_PLAY_CURRENT_HAND]

        self.showCurrentHand(current_hand)
  
        command = { constants.KEY_ACTION :      constants.HAND_UPDATED}

        return command

    # This will aplly a cipher to the card on the deck
    def cipherCard(self,card):
        s = card
        if (len(s) % 16 != 0):
            block = int(len(s)/16)
            block = (block + 1) * 16
            s = s.ljust(block)
        else:
            block = 0      

        # cipher the card
        if(constants.USE_AESCBC):
            card_cipher = cipher_with_symm_key_AESCBC(self.card_cypher_key,s)
        if(constants.USE_AESOFB):
            card_cipher = cipher_with_symm_key_AESOFB(self.card_cypher_key,s)
        if(constants.USE_AESCFB):
            card_cipher = cipher_with_symm_key_AESCFB(self.card_cypher_key,s)

        return card_cipher

    # This will shuffle the deck and send it to the next player
    def shuffleDeck(self, command):

        self.card_cypher_secret = randomSecret()
        self.card_cypher_key = create_symm_key(self.card_cypher_secret)
        
        temp = command[constants.KEY_DECK]
        
        random.shuffle(temp)
        arr = []
        for t in temp:
            if (command[constants.KEY_ACTION] == constants.SEND_DECK_TO_NEXT_PLAYER):
                t = base64.b64decode(t)
            else:
                t = t.encode('utf-8')
                
            arr.append(base64.b64encode(self.cipherCard(t)).decode("utf8").replace("'",'"'))
        
        idx = command[constants.KEY_PLAYER_IDX]
        idx = 0 if idx == 3 else idx + 1

        if (constants.DEBUG_MODE):
            printMessage ("############# APPLIED CYPHER KEY " +  self.card_cypher_secret)

        command = { constants.KEY_ACTION            : constants.SEND_DECK_TO_NEXT_PLAYER,
                    constants.KEY_DECK              : arr,
                    constants.KEY_PLAYER_IDX        : idx,
        }
        
        content = command

        #Passar o objeto de python para json 
        command = json.dumps(content).encode()

        self.deck_shuffled = True
        return command, idx
    
    # This will pick a card from the deck and send the remaining to the next player
    def deckDistribution(self, command):
        deck = command[constants.KEY_DECK]
        deckCount = command[constants.KEY_DECK_COUNT] 
        idxPlayer = command[constants.KEY_PLAYER_IDX]
        idxPlayer = 0 if idxPlayer == 3 else idxPlayer + 1

        if random.randint(0,100) <= constants.PERCENTAGE_CHANCE:
            #The user will pick a card from the deck
            if (constants.DEBUG_MODE):
                printMessage ("I will pick up a card ...")
            if (len(self.hand) < constants.CARDS_IN_HAND ):
                idx =  random.randint(0,deckCount-1)   
                card = deck[idx]
                deck.pop(idx)
                deck.append("Null")
                self.hand.append(card)  # add to hand
                deckCount = deckCount -1
                if deckCount == 0:
                    self.deck_empty = True
            else:
                if (constants.DEBUG_MODE):
                    printMessage ("Skipping card pick up!")
            if (constants.DEBUG_MODE):
                printMessage ("Cards in the Deck: " + str(deckCount))
        else:
            if (len(self.hand) < deckCount):
                maxCards = len(self.hand) 
            else:
                maxCards = deckCount

            cardsToSwitch =  random.randint(0,maxCards) 
            if (constants.DEBUG_MODE):
                printMessage ("I will switch " + str(cardsToSwitch) + " cards ...")
            for i in range(cardsToSwitch):
                idxDeck = random.randint(0,deckCount-1)
                idxHand = random.randint(0, len(self.hand)-1)  
                if (constants.DEBUG_MODE):
                    printMessage ("Deck IDX: " + str(idxDeck) + " | Hand IDX: " + str(idxHand))
                cardDeck = deck[idxDeck]
                cardHand = self.hand[idxHand]
                deck[idxDeck] = cardHand
                self.hand[idxHand] = cardDeck            

        printMessage ("###### I HAVE " + str(len(self.hand)) + " cards!")

        command = { constants.KEY_ACTION            : constants.DECK_DISTRIBUTION,
                    constants.KEY_DECK              : deck,
                    constants.KEY_DECK_COUNT        : deckCount,
                    constants.KEY_PLAYER_IDX        : idxPlayer,
        }
        
        command = json.dumps(command).encode()
       
        return command, idxPlayer

    def doBitCommitment(self,command):

        s = json.dumps(self.hand).encode('utf-8')
        
        if (len(s) % 16 != 0):
            block = int(len(s)/16)
            block = (block + 1) * 16
            s = s.ljust(block)
        else:
            block = 0      

        self.cyphered_hand = s
        self.bit_commitment_r_one = randomNumber()
        self.bit_commitment_r_two = randomNumber()

        #print (s)
        h = hashlib.sha256(self.cyphered_hand)
        h.update(bytes(int(self.bit_commitment_r_one)))
        h.update(bytes(int(self.bit_commitment_r_two)))
        self.bit_commitment = h.hexdigest()

        #print (self.bit_commitment)
   
        command = { constants.KEY_ACTION            : constants.ACK_BIT_COMMITMENT, 
                    constants.KEY_R_ONE             : self.bit_commitment_r_one,
                    constants.KEY_BIT_COMMITMENT    : self.bit_commitment
                    } 

        return command

    def shareCardsCypherKey(self, command):

        self.players_bit_commitments = command[constants.KEY_BIT_COMMITMENT]
        self.players_bit_commitments_r_ones = command[constants.KEY_R_ONE]

        command = { constants.KEY_ACTION        : constants.ACK_DECK_CYPHER_KEY,
                    constants.KEY_DECK_CYPHER   : self.card_cypher_secret
                }

        return command
    
    def decryptHand(self, command):
        keys = command[constants.KEY_CYPHER_ARRAY]
        self.deck_keys = keys
        self.hand = self._decrypt_hand(self.hand)  
        
        #Print Decrypted Hand
        if (constants.DEBUG_MODE):
            printMessage ("MY HAND:")
            print(self.hand)
        
        startPlayer = "0"
        if ('2C' in self.hand):
            printMessage ("I have the two of clubs!")
            startPlayer = "1"

        command = { constants.KEY_ACTION        : constants.ACK_DECRYPT_HAND,
                    constants.KEY_START_PLAYER  : startPlayer
                }

        return command

    def playCard(self, command):
        current_hand = command[constants.KEY_PLAY_CURRENT_HAND]
        first_player = command[constants.KEY_PLAY_FIRST_PLAYER]
        cardToPlay = - 1
    
        cardToPlay = self.showCardPlay(current_hand, first_player)

        if cardToPlay != "00":
            self.hand_played_cards.append(cardToPlay)

            command = { constants.KEY_ACTION        : constants.CARD_PLAYED , 
                        constants.KEY_PLAY_CARD     : cardToPlay
            }
        else:
            command = { constants.KEY_ACTION            : constants.COMPLAIN , 
                        constants.KEY_R_TWO             : self.bit_commitment_r_two,
                        constants.KEY_CIPHERED_HAND     : base64.b64encode(self.cyphered_hand).decode("utf8").replace("'",'"')
                        }

        return command

    def gameOver(self, response):

        history = response[constants.KEY_HISTORY]
        history_points = response[constants.KEY_HISTORY_POINTS] 
        
        ######### RESULT AGREEMENT ############

        points = [0,0,0,0]
        if (len(history) == 13):
            print ("")
            print ("Results:")
            print ("")
            for j in range(len(history)):
                for i in range(4):
                    points[i] =  points[i] + history_points[j][i]

            for i in range(4):
                print('Player %10s: %6d' % (i, points[i]))

        while True:
            try:
                option = str(input("Do you agree with this accounting? (y/n) "))
            except ValueError:
                print("Sorry, Select a valid option")
                continue
            else:
                if option == "y" or option == "n":
                    break
                print("Sorry, Select a valid option")
                continue

        if (option == "y"):

            data = 'Game History' + '\n' + str(history) + '\n\n' + 'Points' + '\n' + str(points) + '\n'
            data = bytes(data, 'utf-8')
            
            # Only save data for the players with CC
            if (self.cc):
                cc = CC()
                identifier = cc.get_number()
                signed = cc.sign(data)
            else:
                exit(0)

            # generate file name
            now = datetime.now()
            dt_string = now.strftime("%d-%m-%Y_%Hh%Mm%S")
            fileName = "historic/" + dt_string + '--Num--' + str(identifier)
         
            save = { 'unsigned' : data, 'signed' : signed }

            # save in file
            with open(fileName, 'wb') as f:
                pickle.dump(save, f, protocol=pickle.HIGHEST_PROTOCOL)

            print("The historic was signed and write in the file: " + dt_string + '--Num--' + str(identifier))

            exit(0)

    def complainSent(self, response):
    
        r_two = int(response[constants.KEY_R_TWO])
        ciphered_hand = base64.b64decode(response[constants.KEY_CIPHERED_HAND])
        player_idx = response[constants.KEY_PLAYER_IDX]
        r_one = int(self.players_bit_commitments_r_ones[player_idx])

        h = hashlib.sha256(ciphered_hand)
        h.update(bytes(r_two))
        h.update(bytes(r_one))

        if (h.hexdigest() == self.players_bit_commitments[player_idx]):
            printMessage("Bit Commitment Verified!")

        command = { constants.KEY_ACTION             :     constants.ACK_COMPLAIN,
                    constants.KEY_R_TWO              :     self.bit_commitment_r_two,
                    constants.KEY_CIPHERED_HAND      :     base64.b64encode(self.cyphered_hand).decode("utf8").replace("'",'"')
                    }
        return command

    def showCardPlay(self, current_hand,first_player):

        # Deck of cards
        deck = ['2C','3C','4C','5C','6C','7C','8C','9C','TC','JC','QC','KC','AC','2D','3D','4D','5D',
                '6D','7D','8D','9D','TD','JD','QD','KD','AD','2S','3S','4S','5S','6S','7S','8S','9S','TS',
                'JS','QS','KS','AS','2H','3H','4H','5H','6H','7H','8H','9H','TH','JH','QH','KH','AH']

        #Print the cards that are being played by all the players  
        print ("\nCurrent hand:")

        print ("|", end='')
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            print('%4d|' % (i+1), end='')  

        print("")
        print ("|", end='')
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            print('%4s|'% ("----"), end='')   
        print("")

        print ("|", end='')
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            print('%4s|' % (current_hand[i]), end='')    
        print("")
        print("")

        #Print the options that the user has in his hand.
        print ("\n My Cards:")
        print("")
        print ("|", end='')
        for i in range(constants.CARDS_IN_HAND):
            print('%4s|'% ("----"), end='')   
        print("")

        print ("|", end='')
        for i in range(constants.CARDS_IN_HAND):
            if self.hand[i] in self.hand_played_cards:
                print('%4s|' % ('* ' + self.hand[i]), end='') 
            else:
                print('%4s|' % (self.hand[i]), end='')    
        print("")
        print("")

        while True:
            try:
                option = input("Please select a card to play or complain (00): ")
            except ValueError:
                print("Sorry, Select a valid option")
                continue
            else:
                
                if option in deck or option == "00":
                    break
                print("Sorry, Select a valid option")
                continue
        
        return option

    def showCurrentHand(self, current_hand):

        #Print the cards that are being played by all the players  
        print ("\nCurrent hand:")

        print ("|", end='')
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            print('%4d|' % (i+1), end='')  

        print("")
        print ("|", end='')
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            print('%4s|'% ("----"), end='')   
        print("")

        print ("|", end='')
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            print('%4s|' % (current_hand[i]), end='')    
        print("")
        print("")

    def showGameOverMenu(self):
        print('End Game')
        
    def show_history (self):
        file = input("Input file name of the history: ")
        fileName = "historic/" + file

        with open(fileName, 'rb') as f:
            b_dict = pickle.load(f)
        signature = b_dict['signed']
        hist = b_dict['unsigned']
        cc = CC()
        certDer = cc.get_cert_der()
        certificate = x509.load_der_x509_certificate(certDer, default_backend())
        public_key = certificate.public_key()

        try :
            public_key.verify ( signature , hist , padding.PKCS1v15() , hashes.SHA1() )
            print ( ' Historic Verified ' )
            print(hist.decode())
        except :
            print ( ' Historic not Verified ' )
            print(hist.decode())
            
        exit(0)

    def menu_game(self):
        while True:
            try:
                option = str(input("Do you want see the history before starting the game? (y/n) "))
            except ValueError:
                print("Sorry, Select a valid option")
                continue
            else:
                
                if option == "y" or option == "n":
                    break
                print("Sorry, Select a valid option")
                continue

        if ( option == "y"):
            self.show_history()

    def _decrypt_hand(self, hand):
        new_hand = hand
        for i in range(4):
            symm_key = create_symm_key(self.deck_keys[i])
            for j in range(constants.CARDS_IN_HAND):
                card = new_hand[j]
                if (i == 0):
                    #print (hand[j])    
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

if 'DEBUG' in sys.argv:
    constants.DEBUG_MODE = True

if 'CC' in sys.argv:
    constants.USE_CC = True

if 'AES-CBC' in sys.argv:
    # dificil prever alterações | AAU na decifra (bloco)
    constants.USE_AESCBC = True

if 'AES-OFB' in sys.argv:
    # continua
    constants.USE_AESOFB = True
    constants.USE_AESCBC = False

if 'AES-CFB' in sys.argv:
    #continua
    constants.USE_AESCFB = True
    constants.USE_AESCBC = False

client = Client("127.0.0.1",constants.SERVER_PORT)
client.listen()