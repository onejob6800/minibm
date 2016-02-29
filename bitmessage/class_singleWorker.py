from __future__ import division

import threading
import shared
import time
from time import strftime, localtime, gmtime
import random
from subprocess import call  # used when the API must execute an outside program
from addresses import *
import highlevelcrypto
import proofofwork
import sys
from helper_sql import *
from helper_generic import addDataPadding

# I don't know what this thread is going to do but it does a lot.

class singleWorker(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            command, data = shared.workerQueue.get()
            if command == 'sendmessage':
                self.sendMsg()
            elif command == 'doPOWForMyV2Pubkey':
                self.doPOWForMyV2Pubkey(data)
            elif command == 'sendOutOrStoreMyV3Pubkey':
                self.sendOutOrStoreMyV3Pubkey(data)
            elif command == 'sendOutOrStoreMyV4Pubkey':
                self.sendOutOrStoreMyV4Pubkey(data)
            else:
                pass

            shared.workerQueue.task_done()

    def doPOWForMyV2Pubkey(self, hash):  # This function also broadcasts out the pubkey message once it is done with the POW
        # Look up my stream number based on my address hash
        """configSections = shared.config.sections()
        for addressInKeysFile in configSections:
            if addressInKeysFile <> 'bitmessagesettings':
                status,addressVersionNumber,streamNumber,hashFromThisParticularAddress = decodeAddress(addressInKeysFile)
                if hash == hashFromThisParticularAddress:
                    myAddress = addressInKeysFile
                    break"""
        myAddress = shared.myAddressesByHash[hash]
        status, addressVersionNumber, streamNumber, hash = decodeAddress(
            myAddress)
        
        TTL = int(28 * 24 * 60 * 60 + random.randrange(-300, 300))# 28 days from now plus or minus five minutes
        embeddedTime = int(time.time() + TTL)
        payload = pack('>Q', (embeddedTime))
        payload += '\x00\x00\x00\x01' # object type: pubkey
        payload += encodeVarint(addressVersionNumber)  # Address version number
        payload += encodeVarint(streamNumber)
        payload += '\x00\x00\x00\x01'  # bitfield of features supported by me (see the wiki).

        try:
            privSigningKeyBase58 = shared.config.get(
                myAddress, 'privsigningkey')
            privEncryptionKeyBase58 = shared.config.get(
                myAddress, 'privencryptionkey')
        except Exception as err:
            return

        privSigningKeyHex = shared.decodeWalletImportFormat(
            privSigningKeyBase58).encode('hex')
        privEncryptionKeyHex = shared.decodeWalletImportFormat(
            privEncryptionKeyBase58).encode('hex')
        pubSigningKey = highlevelcrypto.privToPub(
            privSigningKeyHex).decode('hex')
        pubEncryptionKey = highlevelcrypto.privToPub(
            privEncryptionKeyHex).decode('hex')

        payload += pubSigningKey[1:]
        payload += pubEncryptionKey[1:]

        # Do the POW for this pubkey message
        target = 2 ** 64 / (shared.networkDefaultProofOfWorkNonceTrialsPerByte*(len(payload) + 8 + shared.networkDefaultPayloadLengthExtraBytes + ((TTL*(len(payload)+8+shared.networkDefaultPayloadLengthExtraBytes))/(2 ** 16))))
        initialHash = hashlib.sha512(payload).digest()
        trialValue, nonce = proofofwork.run(target, initialHash)
        payload = pack('>Q', nonce) + payload

        inventoryHash = calculateInventoryHash(payload)
        objectType = 1
        shared.inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime,'')
        shared.inventorySets[streamNumber].add(inventoryHash)

        shared.broadcastToSendDataQueues((
            streamNumber, 'advertiseobject', inventoryHash))
        try:
            shared.config.set(
                myAddress, 'lastpubkeysendtime', str(int(time.time())))
            shared.writeKeysFile()
        except:
            # The user deleted the address out of the keys.dat file before this
            # finished.
            pass

    # If this isn't a chan address, this function assembles the pubkey data,
    # does the necessary POW and sends it out. If it *is* a chan then it
    # assembles the pubkey and stores is in the pubkey table so that we can
    # send messages to "ourselves".
    def sendOutOrStoreMyV3Pubkey(self, hash): 
        try:
            myAddress = shared.myAddressesByHash[hash]
        except:
            #The address has been deleted.
            return
        if shared.safeConfigGetBoolean(myAddress, 'chan'):
            return
        status, addressVersionNumber, streamNumber, hash = decodeAddress(
            myAddress)
        
        TTL = int(28 * 24 * 60 * 60 + random.randrange(-300, 300))# 28 days from now plus or minus five minutes
        embeddedTime = int(time.time() + TTL)
        signedTimeForProtocolV2 = embeddedTime - TTL
        """
        According to the protocol specification, the expiresTime along with the pubkey information is
        signed. But to be backwards compatible during the upgrade period, we shall sign not the 
        expiresTime but rather the current time. There must be precisely a 28 day difference
        between the two. After the upgrade period we'll switch to signing the whole payload with the
        expiresTime time.
        """
        payload = pack('>Q', (embeddedTime))
        payload += '\x00\x00\x00\x01' # object type: pubkey
        payload += encodeVarint(addressVersionNumber)  # Address version number
        payload += encodeVarint(streamNumber)
        payload += '\x00\x00\x00\x01'  # bitfield of features supported by me (see the wiki).

        try:
            privSigningKeyBase58 = shared.config.get(
                myAddress, 'privsigningkey')
            privEncryptionKeyBase58 = shared.config.get(
                myAddress, 'privencryptionkey')
        except Exception as err:
            return

        privSigningKeyHex = shared.decodeWalletImportFormat(
            privSigningKeyBase58).encode('hex')
        privEncryptionKeyHex = shared.decodeWalletImportFormat(
            privEncryptionKeyBase58).encode('hex')
        pubSigningKey = highlevelcrypto.privToPub(
            privSigningKeyHex).decode('hex')
        pubEncryptionKey = highlevelcrypto.privToPub(
            privEncryptionKeyHex).decode('hex')

        payload += pubSigningKey[1:]
        payload += pubEncryptionKey[1:]

        payload += encodeVarint(shared.config.getint(
            myAddress, 'noncetrialsperbyte'))
        payload += encodeVarint(shared.config.getint(
            myAddress, 'payloadlengthextrabytes'))
        
        signature = highlevelcrypto.sign(payload, privSigningKeyHex)
        payload += encodeVarint(len(signature))
        payload += signature

        # Do the POW for this pubkey message
        target = 2 ** 64 / (shared.networkDefaultProofOfWorkNonceTrialsPerByte*(len(payload) + 8 + shared.networkDefaultPayloadLengthExtraBytes + ((TTL*(len(payload)+8+shared.networkDefaultPayloadLengthExtraBytes))/(2 ** 16))))
        initialHash = hashlib.sha512(payload).digest()
        trialValue, nonce = proofofwork.run(target, initialHash)
        payload = pack('>Q', nonce) + payload
        inventoryHash = calculateInventoryHash(payload)
        objectType = 1
        shared.inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime,'')
        shared.inventorySets[streamNumber].add(inventoryHash)

        shared.broadcastToSendDataQueues((
            streamNumber, 'advertiseobject', inventoryHash))
        try:
            shared.config.set(
                myAddress, 'lastpubkeysendtime', str(int(time.time())))
            shared.writeKeysFile()
        except:
            # The user deleted the address out of the keys.dat file before this
            # finished.
            pass

    # If this isn't a chan address, this function assembles the pubkey data,
    # does the necessary POW and sends it out. 
    def sendOutOrStoreMyV4Pubkey(self, myAddress):
        if not shared.config.has_section(myAddress):
            #The address has been deleted.
            return
        if shared.safeConfigGetBoolean(myAddress, 'chan'):
            return
        status, addressVersionNumber, streamNumber, hash = decodeAddress(
            myAddress)
        
        TTL = int(28 * 24 * 60 * 60 + random.randrange(-300, 300))# 28 days from now plus or minus five minutes
        embeddedTime = int(time.time() + TTL)
        payload = pack('>Q', (embeddedTime))
        payload += '\x00\x00\x00\x01' # object type: pubkey
        payload += encodeVarint(addressVersionNumber)  # Address version number
        payload += encodeVarint(streamNumber)

        dataToEncrypt = '\x00\x00\x00\x01'  # bitfield of features supported by me (see the wiki).

        try:
            privSigningKeyBase58 = shared.config.get(
                myAddress, 'privsigningkey')
            privEncryptionKeyBase58 = shared.config.get(
                myAddress, 'privencryptionkey')
        except Exception as err:
            return

        privSigningKeyHex = shared.decodeWalletImportFormat(
            privSigningKeyBase58).encode('hex')
        privEncryptionKeyHex = shared.decodeWalletImportFormat(
            privEncryptionKeyBase58).encode('hex')
        pubSigningKey = highlevelcrypto.privToPub(
            privSigningKeyHex).decode('hex')
        pubEncryptionKey = highlevelcrypto.privToPub(
            privEncryptionKeyHex).decode('hex')
        dataToEncrypt += pubSigningKey[1:]
        dataToEncrypt += pubEncryptionKey[1:]

        dataToEncrypt += encodeVarint(shared.config.getint(
            myAddress, 'noncetrialsperbyte'))
        dataToEncrypt += encodeVarint(shared.config.getint(
            myAddress, 'payloadlengthextrabytes'))
        
        # When we encrypt, we'll use a hash of the data
        # contained in an address as a decryption key. This way in order to
        # read the public keys in a pubkey message, a node must know the address
        # first. We'll also tag, unencrypted, the pubkey with part of the hash
        # so that nodes know which pubkey object to try to decrypt when they
        # want to send a message.
        doubleHashOfAddressData = hashlib.sha512(hashlib.sha512(encodeVarint(
            addressVersionNumber) + encodeVarint(streamNumber) + hash).digest()).digest()
        payload += doubleHashOfAddressData[32:] # the tag
        signature = highlevelcrypto.sign(payload + dataToEncrypt, privSigningKeyHex)
        dataToEncrypt += encodeVarint(len(signature))
        dataToEncrypt += signature
        
        privEncryptionKey = doubleHashOfAddressData[:32]
        pubEncryptionKey = highlevelcrypto.pointMult(privEncryptionKey)
        payload += highlevelcrypto.encrypt(
            dataToEncrypt, pubEncryptionKey.encode('hex'))

        # Do the POW for this pubkey message
        target = 2 ** 64 / (shared.networkDefaultProofOfWorkNonceTrialsPerByte*(len(payload) + 8 + shared.networkDefaultPayloadLengthExtraBytes + ((TTL*(len(payload)+8+shared.networkDefaultPayloadLengthExtraBytes))/(2 ** 16))))
        initialHash = hashlib.sha512(payload).digest()
        trialValue, nonce = proofofwork.run(target, initialHash)

        payload = pack('>Q', nonce) + payload
        inventoryHash = calculateInventoryHash(payload)
        objectType = 1
        shared.inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime, doubleHashOfAddressData[32:])
        shared.inventorySets[streamNumber].add(inventoryHash)

        shared.broadcastToSendDataQueues((
            streamNumber, 'advertiseobject', inventoryHash))
        try:
            shared.config.set(
                myAddress, 'lastpubkeysendtime', str(int(time.time())))
            shared.writeKeysFile()
        except Exception as err:
            pass

    def processMessageWithQueuedStatus(self):
        ret = sqlQuery("SELECT toaddress FROM sent WHERE status='msgqueued' and folder='sent'")
        for row in ret:
            toaddress = row[0]
            toStatus, toAddressVersionNumber, toStreamNumber, toRipe = decodeAddress(toaddress)
            # If we are sending a message to ourselves or a chan then we won't need an entry in the pubkeys table; 
            # We can calculate the needed pubkey using the private keys in our keys.dat file.
            if shared.config.has_section(toaddress):
                sqlExecute(
                    '''UPDATE sent SET status='doingmsgpow' WHERE toaddress=?''',
                    toaddress)
            else:
                # Let's see if we already have the pubkey in our pubkeys table
                # If we have the needed pubkey in the pubkey table already, 
                if toaddress in shared.hadPubkeys.keys():
                    # set the status of this msg to doingmsgpow
                    sqlExecute('''UPDATE sent SET status='doingmsgpow' WHERE toaddress=? ''', toaddress)
                # We don't have the needed pubkey in the pubkeys table already.
                else:
                    if toAddressVersionNumber <= 3:
                        toTag = ''
                    else:
                        toTag = hashlib.sha512(hashlib.sha512(encodeVarint(toAddressVersionNumber)+encodeVarint(toStreamNumber)+toRipe).digest()).digest()[32:]
                    if toaddress in shared.neededPubkeys or toTag in shared.neededPubkeys:
                        # We already sent a request for the pubkey
                        # Maybe another message already did this.
                        sqlExecute(
                            '''UPDATE sent SET status='awaitingpubkey', sleeptill=? WHERE toaddress=? AND status='msgqueued' ''', 
                            int(time.time()) + 2.5*24*60*60,
                            toaddress)
                    else:
                        sqlExecute(
                            '''UPDATE sent SET status='doingpubkeypow' WHERE toaddress=? AND status='msgqueued' ''',
                            toaddress)
                        self.requestPubKey(toaddress)


    
    def processMessageWithPOWStatus(self):
        ret = sqlQuery(
                '''SELECT toaddress, fromaddress, subject, message, ackdata, status, ttl, retrynumber FROM sent WHERE (status='doingmsgpow' or status='forcepow') and folder='sent' ''')
        for row in ret:
            # Decode data from query
            toaddress, fromaddress, subject, message, ackdata, status, TTL, retryNumber = row 
            toStatus, toAddressVersionNumber, toStreamNumber, toRipe = decodeAddress(toaddress)
            fromStatus, fromAddressVersionNumber, fromStreamNumber, fromRipe = decodeAddress(fromaddress)
            
            # Set TTL
            if retryNumber == 0:
                if TTL > 28 * 24 * 60 * 60:
                    TTL = 28 * 24 * 60 * 60
            else:
                TTL = 28 * 24 * 60 * 60 
            TTL = int(TTL + random.randrange(-300, 300))# add some randomness to the TTL
            embeddedTime = int(time.time() + TTL)
            # Get pubkey 
            if not shared.config.has_section(toaddress): # if we aren't sending this to ourselves or a chan
                shared.ackdataForWhichImWatching[ackdata] = 0
                # Let us fetch the recipient's public key out of our database. If
                # the required proof of work difficulty is too hard then we'll
                # abort.
		pubkeyPayload = shared.hadPubkeys[toaddress][2]

                # The pubkey message is stored with the following items all appended:
                #    -address version
                #    -stream number
                #    -behavior bitfield
                #    -pub signing key
                #    -pub encryption key
                #    -nonce trials per byte (if address version is >= 3) 
                #    -length extra bytes (if address version is >= 3)

                readPosition = 1  # to bypass the address version whose length is definitely 1
                streamNumber, streamNumberLength = decodeVarint(
                    pubkeyPayload[readPosition:readPosition + 10])
                readPosition += streamNumberLength
                behaviorBitfield = pubkeyPayload[readPosition:readPosition + 4]
                # Mobile users may ask us to include their address's RIPE hash on a message
                # unencrypted. Before we actually do it the sending human must check a box
                # in the settings menu to allow it.
                if shared.isBitSetWithinBitfield(behaviorBitfield,30): # if receiver is a mobile device who expects that their address RIPE is included unencrypted on the front of the message..
                    if not shared.safeConfigGetBoolean('bitmessagesettings','willinglysendtomobile'): # if we are Not willing to include the receiver's RIPE hash on the message..
                        # if the human changes their setting and then sends another message or restarts their client, this one will send at that time.
                        continue
                readPosition += 4  # to bypass the bitfield of behaviors
                # pubSigningKeyBase256 = pubkeyPayload[readPosition:readPosition+64] # We don't use this key for anything here.
                readPosition += 64
                pubEncryptionKeyBase256 = pubkeyPayload[readPosition:readPosition + 64]
                readPosition += 64

                # Let us fetch the amount of work required by the recipient.
                if toAddressVersionNumber == 2:
                    requiredAverageProofOfWorkNonceTrialsPerByte = shared.networkDefaultProofOfWorkNonceTrialsPerByte
                    requiredPayloadLengthExtraBytes = shared.networkDefaultPayloadLengthExtraBytes
                elif toAddressVersionNumber >= 3:
                    requiredAverageProofOfWorkNonceTrialsPerByte, varintLength = decodeVarint(
                        pubkeyPayload[readPosition:readPosition + 10])
                    readPosition += varintLength
                    requiredPayloadLengthExtraBytes, varintLength = decodeVarint(
                        pubkeyPayload[readPosition:readPosition + 10])
                    readPosition += varintLength
                    if requiredAverageProofOfWorkNonceTrialsPerByte < shared.networkDefaultProofOfWorkNonceTrialsPerByte:  # We still have to meet a minimum POW difficulty regardless of what they say is allowed in order to get our message to propagate through the network.
                        requiredAverageProofOfWorkNonceTrialsPerByte = shared.networkDefaultProofOfWorkNonceTrialsPerByte
                    if requiredPayloadLengthExtraBytes < shared.networkDefaultPayloadLengthExtraBytes:
                        requiredPayloadLengthExtraBytes = shared.networkDefaultPayloadLengthExtraBytes
                    if status != 'forcepow':
                        if (requiredAverageProofOfWorkNonceTrialsPerByte > shared.config.getint('bitmessagesettings', 'maxacceptablenoncetrialsperbyte') and shared.config.getint('bitmessagesettings', 'maxacceptablenoncetrialsperbyte') != 0) or (requiredPayloadLengthExtraBytes > shared.config.getint('bitmessagesettings', 'maxacceptablepayloadlengthextrabytes') and shared.config.getint('bitmessagesettings', 'maxacceptablepayloadlengthextrabytes') != 0):
                            # The demanded difficulty is more than we are willing
                            # to do.
                            sqlExecute(
                                '''UPDATE sent SET status='toodifficult' WHERE ackdata=? ''',
                                ackdata)
                            continue
            else: # if we are sending a message to ourselves or a chan..
                behaviorBitfield = '\x00\x00\x00\x01'

                try:
                    privEncryptionKeyBase58 = shared.config.get(
                        toaddress, 'privencryptionkey')
                except Exception as err:
                    continue
                privEncryptionKeyHex = shared.decodeWalletImportFormat(
                    privEncryptionKeyBase58).encode('hex')
                pubEncryptionKeyBase256 = highlevelcrypto.privToPub(
                    privEncryptionKeyHex).decode('hex')[1:]
                requiredAverageProofOfWorkNonceTrialsPerByte = shared.networkDefaultProofOfWorkNonceTrialsPerByte
                requiredPayloadLengthExtraBytes = shared.networkDefaultPayloadLengthExtraBytes
            # Now we can start to assemble our message.
            payload = encodeVarint(fromAddressVersionNumber)
            payload += encodeVarint(fromStreamNumber)
            payload += '\x00\x00\x00\x01'  # Bitfield of features and behaviors that can be expected from me. (See https://bitmessage.org/wiki/Protocol_specification#Pubkey_bitfield_features  )

            # We need to convert our private keys to public keys in order
            # to include them.
            try:
                privSigningKeyBase58 = shared.config.get(
                    fromaddress, 'privsigningkey')
                privEncryptionKeyBase58 = shared.config.get(
                    fromaddress, 'privencryptionkey')
            except:
                continue

            privSigningKeyHex = shared.decodeWalletImportFormat(
                privSigningKeyBase58).encode('hex')
            privEncryptionKeyHex = shared.decodeWalletImportFormat(
                privEncryptionKeyBase58).encode('hex')

            pubSigningKey = highlevelcrypto.privToPub(
                privSigningKeyHex).decode('hex')
            pubEncryptionKey = highlevelcrypto.privToPub(
                privEncryptionKeyHex).decode('hex')

            payload += pubSigningKey[
                1:]  # The \x04 on the beginning of the public keys are not sent. This way there is only one acceptable way to encode and send a public key.
            payload += pubEncryptionKey[1:]

            if fromAddressVersionNumber >= 3:
                # If the receiver of our message is in our address book,
                # subscriptions list, or whitelist then we will allow them to
                # do the network-minimum proof of work. Let us check to see if
                # the receiver is in any of those lists.
                payload += encodeVarint(shared.config.getint(
                    fromaddress, 'noncetrialsperbyte'))
                payload += encodeVarint(shared.config.getint(
                    fromaddress, 'payloadlengthextrabytes'))

            payload += toRipe  # This hash will be checked by the receiver of the message to verify that toRipe belongs to them. This prevents a Surreptitious Forwarding Attack.
            payload += '\x02'  # Type 2 is simple UTF-8 message encoding as specified on the Protocol Specification on the Bitmessage Wiki.
            messageToTransmit = 'Subject:' + subject + '\n' 
            messageToTransmit+= 'Body:' + message
            payload += encodeVarint(len(messageToTransmit))
            payload += messageToTransmit
            if shared.config.has_section(toaddress):
                fullAckPayload = ''
            elif not shared.isBitSetWithinBitfield(behaviorBitfield,31):
                fullAckPayload = ''                    
            else:
                fullAckPayload = self.generateFullAckMessage(
                    ackdata, toStreamNumber, TTL)  # The fullAckPayload is a normal msg protocol message with the proof of work already completed that the receiver of this message can easily send out.
            payload += encodeVarint(len(fullAckPayload))
            payload += fullAckPayload
            dataToSign = pack('>Q', embeddedTime) + '\x00\x00\x00\x02' + encodeVarint(1) + encodeVarint(toStreamNumber) + payload 
            signature = highlevelcrypto.sign(dataToSign, privSigningKeyHex)
            payload += encodeVarint(len(signature))
            payload += signature

            # We have assembled the data that will be encrypted.
            try:
                encrypted = highlevelcrypto.encrypt(payload,"04"+pubEncryptionKeyBase256.encode('hex'))
            except:
                sqlExecute('''UPDATE sent SET status='badkey' WHERE ackdata=?''', ackdata)
                continue
            
            encryptedPayload = pack('>Q', embeddedTime)
            encryptedPayload += '\x00\x00\x00\x02' # object type: msg
            encryptedPayload += encodeVarint(1) # msg version
            encryptedPayload += encodeVarint(toStreamNumber) + encrypted
            target = 2 ** 64 / (requiredAverageProofOfWorkNonceTrialsPerByte*(len(encryptedPayload) + 8 + requiredPayloadLengthExtraBytes + ((TTL*(len(encryptedPayload)+8+requiredPayloadLengthExtraBytes))/(2 ** 16))))
            powStartTime = time.time()
            initialHash = hashlib.sha512(encryptedPayload).digest()
            trialValue, nonce = proofofwork.run(target, initialHash)

            encryptedPayload = pack('>Q', nonce) + encryptedPayload
            
            # Sanity check. The encryptedPayload size should never be larger than 256 KiB. There should
            # be checks elsewhere in the code to not let the user try to send a message this large
            # until we implement message continuation. 
            if len(encryptedPayload) > 2 ** 18: # 256 KiB
                print "The payload is lager than 256KiB,So the loop will continue"
                continue

            inventoryHash = calculateInventoryHash(encryptedPayload)
            objectType = 2
            shared.inventory[inventoryHash] = (
                objectType, toStreamNumber, encryptedPayload, embeddedTime, '')
            shared.inventorySets[toStreamNumber].add(inventoryHash)
            shared.broadcastToSendDataQueues((
                toStreamNumber, 'advertiseobject', inventoryHash))

            # Update the sent message in the sent table with the necessary information.
            if shared.config.has_section(toaddress):
                newStatus = 'msgsentnoackexpected'
            else:
                newStatus = 'msgsent'
            if retryNumber == 0:
                sleepTill = int(time.time()) + TTL
            else:
                sleepTill = int(time.time()) + 28*24*60*60 * 2**retryNumber
            sqlExecute('''UPDATE sent SET msgid=?, status=?, retrynumber=?, sleeptill=?, lastactiontime=? WHERE ackdata=?''',
                       inventoryHash,
                       newStatus,
                       retryNumber+1,
                       sleepTill,
                       int(time.time()),
                       ackdata)

            # If we are sending to ourselves or a chan, let's put the message in our own inbox.
            if shared.config.has_section(toaddress):
                sigHash = hashlib.sha512(hashlib.sha512(signature).digest()).digest()[32:] # Used to detect and ignore duplicate messages in our inbox
                t = (inventoryHash, toaddress, fromaddress, subject, int(
                    time.time()), message, 'inbox', 2, 0, sigHash)
                shared.messages.append(t)

    def sendMsg(self):
        self.processMessageWithQueuedStatus()
        self.processMessageWithPOWStatus()

    def requestPubKey(self, toAddress):
        toStatus, addressVersionNumber, streamNumber, ripe = decodeAddress(
            toAddress)
        if toStatus != 'success':
            return
        
        queryReturn = sqlQuery(
            '''SELECT retrynumber FROM sent WHERE toaddress=? AND (status='doingpubkeypow' OR status='awaitingpubkey') LIMIT 1''', 
            toAddress)
        if len(queryReturn) == 0:
            return
        retryNumber = queryReturn[0][0]

        if addressVersionNumber <= 3:
            shared.neededPubkeys[toAddress] = 0
        elif addressVersionNumber >= 4:
            # If the user just clicked 'send' then the tag (and other information) will already
            # be in the neededPubkeys dictionary. But if we are recovering from a restart
            # of the client then we have to put it in now. 
            privEncryptionKey = hashlib.sha512(hashlib.sha512(encodeVarint(addressVersionNumber)+encodeVarint(streamNumber)+ripe).digest()).digest()[:32] # Note that this is the first half of the sha512 hash.
            tag = hashlib.sha512(hashlib.sha512(encodeVarint(addressVersionNumber)+encodeVarint(streamNumber)+ripe).digest()).digest()[32:] # Note that this is the second half of the sha512 hash.
            if tag not in shared.neededPubkeys:
                shared.neededPubkeys[tag] = (toAddress, highlevelcrypto.makeCryptor(privEncryptionKey.encode('hex'))) # We'll need this for when we receive a pubkey reply: it will be encrypted and we'll need to decrypt it.
        
        if retryNumber == 0:
            TTL = 2.5*24*60*60 # 2.5 days. This was chosen fairly arbitrarily. 
        else:
            TTL = 28*24*60*60
        TTL = TTL + random.randrange(-300, 300) # add some randomness to the TTL
        embeddedTime = int(time.time() + TTL)
        payload = pack('>Q', embeddedTime)
        payload += '\x00\x00\x00\x00' # object type: getpubkey
        payload += encodeVarint(addressVersionNumber)
        payload += encodeVarint(streamNumber)
        if addressVersionNumber <= 3:
            payload += ripe
        else:
            payload += tag

        statusbar = 'Doing the computations necessary to request the recipient\'s public key.'
        
        target = 2 ** 64 / (shared.networkDefaultProofOfWorkNonceTrialsPerByte*(len(payload) + 8 + shared.networkDefaultPayloadLengthExtraBytes + ((TTL*(len(payload)+8+shared.networkDefaultPayloadLengthExtraBytes))/(2 ** 16))))
        initialHash = hashlib.sha512(payload).digest()
        trialValue, nonce = proofofwork.run(target, initialHash)
        payload = pack('>Q', nonce) + payload
        inventoryHash = calculateInventoryHash(payload)
        objectType = 1
        shared.inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime, '')
        shared.inventorySets[streamNumber].add(inventoryHash)
        shared.broadcastToSendDataQueues((
            streamNumber, 'advertiseobject', inventoryHash))
        
        if retryNumber == 0:
            sleeptill = int(time.time()) + TTL
        else:
            sleeptill = int(time.time()) + 28*24*60*60 * 2**retryNumber
        sqlExecute(
            '''UPDATE sent SET lastactiontime=?, status='awaitingpubkey', retrynumber=?, sleeptill=? WHERE toaddress=? AND (status='doingpubkeypow' OR status='awaitingpubkey') ''',
            int(time.time()),
            retryNumber+1,
            sleeptill,
            toAddress)

    def generateFullAckMessage(self, ackdata, toStreamNumber, TTL):
        
        # It might be perfectly fine to just use the same TTL for
        # the ackdata that we use for the message. But I would rather
        # it be more difficult for attackers to associate ackData with 
        # the associated msg object. However, users would want the TTL
        # of the acknowledgement to be about the same as they set
        # for the message itself. So let's set the TTL of the 
        # acknowledgement to be in one of three 'buckets': 1 hour, 7 
        # days, or 28 days, whichever is relatively close to what the 
        # user specified.
        if TTL < 24*60*60: # 1 day
            TTL = 24*60*60 # 1 day
        elif TTL < 7*24*60*60: # 1 week
            TTL = 7*24*60*60 # 1 week
        else:
            TTL = 28*24*60*60 # 4 weeks
        TTL = int(TTL + random.randrange(-300, 300)) # Add some randomness to the TTL
        embeddedTime = int(time.time() + TTL)
        payload = pack('>Q', (embeddedTime))
        payload += '\x00\x00\x00\x02' # object type: msg
        payload += encodeVarint(1) # msg version
        payload += encodeVarint(toStreamNumber) + ackdata
        
        target = 2 ** 64 / (shared.networkDefaultProofOfWorkNonceTrialsPerByte*(len(payload) + 8 + shared.networkDefaultPayloadLengthExtraBytes + ((TTL*(len(payload)+8+shared.networkDefaultPayloadLengthExtraBytes))/(2 ** 16))))

        powStartTime = time.time()
        initialHash = hashlib.sha512(payload).digest()
        trialValue, nonce = proofofwork.run(target, initialHash)
        payload = pack('>Q', nonce) + payload
        return shared.CreatePacket('object', payload)
