import constants
import random
from cryptography.hazmat.primitives import serialization
from threading import Lock

class User:

    def __init__(self, thread):
        self.id = thread                # ID da thread criada
        self.status = 1
        self.username = None
        self.identification = None
        self.pub_key = None
        self.pub_key_bytes = None
        self.commands = []              # Server Commands
        self.userCommands = []          # User Commands

    def setUserName(self, username):
        self.username = username
   
    def setIdentification(self, identification):
        self.identification = identification

    def setPublicKey(self, pub_key):
        self.pub_key = pub_key
        self.pub_key_bytes = self.pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def setPublicKeyBytes(self, pub_key_bytes):
        self.pub_key_bytes = pub_key_bytes

    def getCommands(self):
        return self.commands
    
    def getUserCommands(self):
        return self.userCommands

    def getUserName(self):
        return self.username
    
    def getIdentification(self):
        return self.identification

    def getPublicKey(self):
        return self.pub_key
    
    def getPublicKeyBytes(self):
        return self.pub_key_bytes.decode("utf8").replace("'",'"')

    def getId(self):
        return self.id  
    
    def __str__(self):
        return self.username 

class Table:
    
    # Deck of cards
    deck = ['2C','3C','4C','5C','6C','7C','8C','9C','TC','JC','QC','KC','AC','2D','3D','4D','5D',
            '6D','7D','8D','9D','TD','JD','QD','KD','AD','2S','3S','4S','5S','6S','7S','8S','9S','TS',
            'JS','QS','KS','AS','2H','3H','4H','5H','6H','7H','8H','9H','TH','JH','QH','KH','AH']

    def __init__(self, id):

        # Variables for handling security 

        self.ack_public_keys = [0,0,0,0]                  # Identifies if the users have sent an ACK about receiving the public keys
        self.ack_public_keys_lock = Lock()
        self.ack_bit_commitments = [0,0,0,0]              # Identifies if the users have sent an ACK about bit commitments
        self.ack_bit_commitments_lock = Lock()
        self.ack_deck_cypher_key = [0,0,0,0]              # Identifies if the users have sent an ACK about the deck cypher
        self.ack_deck_cypher_key_lock = Lock()
        self.ack_decrypt_hand = [0,0,0,0]                 # Identifies if the users have sent an ACK about decrypting their hand
        self.ack_decrypt_hand_lock = Lock()
        self.ack_complain = [0,0,0,0]                     # Identifies if the users have sent an ACK about the complain
        self.ack_complain_lock = Lock()
        self.deck_cypher_keys = [None,None,None,None]     # Array that will hold the cypher keys
        
        # Variables for handling the game 
        
        self.id = id                                      # User Identifier in the game
        self.users = []                                   # Identifies all the users in the table
        self.history = []                                 # History of the hands that where played by each player 
        self.history_points = []                          # History of the points of each player on each hand
        self.history_winner = []                          # Player who won the hand
        self.history_start_player = []                    # Player who started the hand
        self.status = constants.TABLE_STATUS_OPEN         # Identifies the status of the table (can be open, start game, end game)
        self.user_start_idx = None                        # Index of the user that started the cypher (shuffle) 
        self.user_start_game_idx = None                   # Index of the user who is going to start to play the game (has the two of clubs)
        self.current_hand = ['','','','']                 # Saves the current hand on the game  
        self.current_hand_start_player_idx = None         # Sets the player that has started playing the current hand   
        self.bit_commitments = ['','','','']              # Saves the bit commitments of each player
        self.bit_commitments_r_ones = ['','','','']       # Saves the r one of each player
        self.complain_r_twos = ['','','','']              # Saves the r two of each player
        self.complain_hands = ['','','','']               # Saves the hands 
        self.complain_idx_player = -1                     # Player that complained
        self.complain_decryted_hands = ['','','','']      # Players decrypted hands   

    def playHand(self, card, user):
        self.current_hand[user] = card 
        self.printCurrentHand()
        if (self.isHandComplete()):
            idx = self.checkHandWinner()
            self.setCurrentHandStartPlayerIdx(idx)
            u = self.getUser(idx)    
            print ('The User ' + u.getUserName() + " won this hand!")
            self.current_hand = ['','','',''] 
            return idx
        else:
            #Send the idx of the next player
            if (user == 3):
                return 0 
            else:
                return user + 1     

    #Check the Player that won the Hand
    def checkHandWinner(self):
        order = ['2','3','4','5','6','7','8','9','T','J','Q','K','A']
        startPlayerIdx = self.current_hand_start_player_idx
        cardValue = self.current_hand[startPlayerIdx][0] 
        cardSuit = self.current_hand[startPlayerIdx][1] 

        cardMaxValue = cardValue
        winner = startPlayerIdx
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            if (i != startPlayerIdx):
                handCardValue = self.current_hand[i][0] 
                handCardSuit = self.current_hand[i][1] 
                if (handCardSuit == cardSuit):
                    if (order.index(cardMaxValue) < order.index(handCardValue)):
                        cardMaxValue = handCardValue
                        winner = i

        self.history.append(self.current_hand)
        #save the points 
        points = []
        winners = []
        sum_points = 0
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            if i != winner:
                points.append(0)
                winners.append(0)
            else:
                for j in range(constants.TABLE_NUMBER_OF_PLAYERS):
                    if (self.current_hand[j] == 'QS'):
                        sum_points += 13
                    else:
                        handCardSuit = self.current_hand[j][1] 
                        if (handCardSuit == 'H'):
                            sum_points += 1
                points.append(sum_points)
                winners.append(1)

        self.history_points.append(points)
        self.history_winner.append(winners)
        self.history_start_player.append(startPlayerIdx)
        self.printHistory()
        return winner

    def printCurrentHand(self):

        #Print the cards that are being played by all the players  
        print ("\nCURRENT HAND:")

        print ("|", end='')
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            print('%8s|' % (self.users[i].getUserName()), end='')  

        print("")
        print ("|", end='')
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            print('%8s|'% ("----"), end='')   
        print("")

        print ("|", end='')
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            print('%8s|' % (self.current_hand[i]), end='')    
        print("")
        print("")

    def printHistory(self):

        #Print the cards that are being played by all the players  
        print ("HISTORY:")

        print ("|", end='')
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            print('%16s|' % (self.users[i].getUserName()), end='')  

        print("")
        print ("|", end='')
        for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
            print('%16s|'% ("----"), end='')   
        print("")

        
        for j in range(len(self.history)):
            print ("|", end='')
            hand = self.history[j]
            points = self.history_points[j]
            winner = self.history_winner[j]
            for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
                s = hand[i] + " / " + str(points[i])
                if (winner[i] == 1):
                    s = s + " *"
                print('%16s|' % (s), end='')    
            print("")
        
        #Vamos imprimir os resultados do fim do jogo 
        #Vamos somar os pontos
        points = [0,0,0,0]
        if (len(self.history) == 13):
            print ("")
            print ("Results:")
            print ("")
            for j in range(len(self.history)):
                for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
                    points[i] =  points[i] + self.history_points[j][i]

            for i in range(constants.TABLE_NUMBER_OF_PLAYERS):
                print('%10s: %6d' % (self.users[i].getUserName(), points[i]))              

    def verifyComplain(self):
        self.printHistory()
        cheats = [0,0,0,0]
        for u in self.users:
            idx = self.getUserIndex(u)
            hand = self.complain_decryted_hands[idx] 

            cardsSuits = {'H':0, 'S': 0, 'C': 0, 'D': 0} 

            for i in range (constants.CARDS_IN_HAND):
                handCardSuit = hand[i][1] 
                cardsSuits[handCardSuit] = cardsSuits[handCardSuit] + 1

            for i in range(len(self.history)): 
               startPlayer = self.history_start_player[i]
               handCardSuit = self.history[i][startPlayer][1] 
    
               if (cardsSuits[handCardSuit] > 0):
                    playedCardSuit = self.history[i][idx][1] 
                    if (playedCardSuit != handCardSuit):
                        cheats[idx] = 1
                        print ("Player " + self.users[idx].getUserName() + " didn't played the same suit of card in a hand!")
                        continue

                    cardsSuits[handCardSuit] = cardsSuits[handCardSuit] -1

            playedCards = []
            for i in range(len(self.history)): 
                card = self.history[i][idx]
                if not card in hand:
                    cheats[idx] = 1
                    print ("Player " + self.users[idx].getUserName() + " played a card that wasn't part of his hand!")
                    continue
                playedCards.append(card)

            for i in range(len(playedCards)):      
                if (playedCards.count(playedCards[i]) > 1):
                    cheats[idx] = 1
                    print ("Player " + self.users[idx].getUserName() + " played the same card " + playedCards[i] + " more than once!")
                    continue

                
        return     

    def setComplainDecryptedHands(self, hand, idx):
        self.complain_decryted_hands[idx] = hand

    # Validates if all the players have played the hand
    def isHandComplete(self):
        for card in self.current_hand:
            if card == '':
               return False
        return True     

    def getCypherKeysArray(self):
        arr=[]
        idx = self.user_start_idx
        for i in range(4):
            arr.append(self.deck_cypher_keys[idx]) 
            if (idx == 3):
                idx = 0
            else:
                idx = idx + 1

        return list(reversed(arr))
    
    def setCypherKey(self, user, key):
        idx = self.getUserIndex(user)
        self.deck_cypher_keys[idx] = key

    # Defines that we have enough players to play the game
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
        with self.ack_public_keys_lock:
            self.ack_public_keys[idx]=1

    # Set in the ack bit commitment array that the user has sent an ACK about doing the bit commitment
    def setUserACKBitCommitment(self, user, bit_commitment, r_one):
        idx = self.getUserIndex(user)
        self.bit_commitments[idx] = bit_commitment
        self.bit_commitments_r_ones[idx] = r_one
        with self.ack_bit_commitments_lock:
            self.ack_bit_commitments[idx]=1

    # Set in the ack deck array that the user has sent an ACK about sharing the key
    def setUserACKDeckCypherKey(self, user):
        idx = self.getUserIndex(user)
        with self.ack_deck_cypher_key_lock:
            self.ack_deck_cypher_key[idx]=1

    # Set in the ack decrypt hand array that the user has sent an ACK about decrypting his hand
    def setUserACKDecryptHand(self, user):
        idx = self.getUserIndex(user)
        with self.ack_decrypt_hand_lock:
            self.ack_decrypt_hand[idx]=1
    
    # Set in the ack decrypt hand array that the user has sent an ACK about decrypting his hand
    def setUserACKComplain(self, user, r_two, ciphered_hand):
        idx = self.getUserIndex(user)
        with self.ack_complain_lock:
            self.ack_complain[idx]=1
            self.complain_r_twos[idx] = r_two
            self.complain_hands[idx] = ciphered_hand

    # Verify if we are able to send the deck to the players, all the ack must have been sent by the users
    def canDeckBeSent(self):
        result = False
        with self.ack_public_keys_lock:
            result =  all([ack_pub for ack_pub in self.ack_public_keys])
        return result
    
    # Verify if we are able to send the deck for decryption (after the bit commitment)
    def canDeckBeDecrypted(self):
        result = False
        with self.ack_bit_commitments_lock:
            result =  all([bit_comm for bit_comm in self.ack_bit_commitments])
        return result

    # Verify if we are able to send the deck for decryption (after the bit commitment)
    def canStartGame(self):
        result = False
        with self.ack_decrypt_hand_lock:
            result =  all([dec_hand for dec_hand in self.ack_decrypt_hand])
        return result

    # Verify if we are able to send the deck for decryption (after the bit commitment)
    def canDeckCypherKeysBeShared(self):
        result = False
        with self.ack_deck_cypher_key_lock:
            result =  all([cipher_key for cipher_key in self.ack_deck_cypher_key])
        return result

    def canExecuteComplain(self):
        result = False
        with self.ack_complain_lock:
            result =  all([bit_comm for bit_comm in self.ack_complain])
        return result

    # Returns if the user is in this table
    def isUserInTable(self, user):
        return (user in self.users)

    def startGame(self):
        self.status = constants.TABLE_STATUS_GAME_START

    def getRandomUser(self):
        idx = random.randint(0,constants.TABLE_NUMBER_OF_PLAYERS-1)
        return self.users[idx], idx

    def getShuffledDeck(self):
        random.shuffle(self.deck)
        return self.deck

    def join(self, user):
        if user not in self.users:
            self.users.append(user)

    def leave(self, user):
        if user in self.users:
            self.users.remove(user)

    def getUser(self, idx):
        return self.users[idx]
    

# NORMAL GETTERS AND SETTERS

    def getHistory(self):
        return self.history

    def getHistoryPoints(self):
        return self.history_points

    def getComplainHands (self):
        return self.complain_hands

    # Returns all the bit commitments
    def getBitCommitments(self):
        return self.bit_commitments

    # Returns all the bit commitments
    def getBitCommitmentsROnes(self):
        return self.bit_commitments_r_ones

    # Returns all the users
    def getUsers(self):
        return self.users

    # Returns the player identifier
    def getId(self):
        return self.id

    # Returns the current hand on the game
    def getCurrentHand(self):
        return self.current_hand

    # Returns the status of the table
    def getStatus(self):
        return self.status

    # Sets the index of the user that has started the deck distribution
    def setUserStartIdx(self, idx):
        self.user_start_idx = idx

    # Gets the index of the user that has started the deck distribution
    def getUserStartIdx(self):
        return self.user_start_idx

    # Sets the index of the user that has started the game (two of clubs)
    def setUserStartGameIdx(self, idx):
        self.user_start_game_idx = idx

    # Sets the player that has started to play the current hand
    def setCurrentHandStartPlayerIdx(self, idx):
        self.current_hand_start_player_idx = idx
    
    # Gets the player that has started to play the current hand
    def getCurrentHandStartPlayerIdx(self):
        return self.current_hand_start_player_idx
    
    # Gets the player that has started to play the current hand
    def getHistory(self):
        return self.history