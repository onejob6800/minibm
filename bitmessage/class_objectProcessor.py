import time
import threading
import shared
import hashlib
import random
from struct import unpack, pack
import sys
import string
from subprocess import call  # used when the API must execute an outside program
import traceback
import sqlite3

from pyelliptic.openssl import OpenSSL
import highlevelcrypto
from addresses import *
import helper_generic
from helper_generic import addDataPadding
from helper_sql import *


class objectProcessor(threading.Thread):
    """
    The objectProcessor thread, of which there is only one, receives network
    objecs (msg, broadcast, pubkey, getpubkey) from the receiveDataThreads.
    """
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            objectType, data = shared.objectProcessorQueue.get()
            try:
                if objectType == 0: # getpubkey
                    self.processgetpubkey(data)
                elif objectType == 1: #pubkey
                    self.processpubkey(data)
                elif objectType == 2: #msg
                    self.processmsg(data)
                elif objectType == 3: #broadcast
                    # Just ignore broadcast because we don't need it.
                    pass
                elif objectType == 'checkShutdownVariable': # is more of a command, not an object type. Is used to get this thread past the queue.get() so that it will check the shutdown variable.
                    pass
                else:
                    pass
            except varintDecodeError as e:
                pass
            except Exception as e:
                pass

            with shared.objectProcessorQueueSizeLock:
                shared.objectProcessorQueueSize -= len(data) # We maintain objectProcessorQueueSize so that we will slow down requesting objects if too much data accumulates in the queue.

            if shared.shutdown:
                time.sleep(.5) # Wait just a moment for most of the connections to close
                numberOfObjectsThatWereInTheObjectProcessorQueue = 0
                with SqlBulkExecute() as sql:
                    while shared.objectProcessorQueueSize > 1:
                        objectType, data = shared.objectProcessorQueue.get()
                        sql.execute('''INSERT INTO objectprocessorqueue VALUES (?,?)''',
                                   objectType,data)
                        with shared.objectProcessorQueueSizeLock:
                            shared.objectProcessorQueueSize -= len(data) # We maintain objectProcessorQueueSize so that we will slow down requesting objects if too much data accumulates in the queue.
                        numberOfObjectsThatWereInTheObjectProcessorQueue += 1
                shared.shutdown = 2
                break
    
    def processgetpubkey(self, data):
        readPosition = 20  # bypass the nonce, time, and object type
        requestedAddressVersionNumber, addressVersionLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += addressVersionLength
        streamNumber, streamNumberLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += streamNumberLength

        myAddress = ''
        if requestedAddressVersionNumber <= 3 :
            requestedHash = data[readPosition:readPosition + 20]
            if len(requestedHash) != 20:
                return
            if requestedHash in shared.myAddressesByHash:  # if this address hash is one of mine
                myAddress = shared.myAddressesByHash[requestedHash]
        elif requestedAddressVersionNumber >= 4:
            requestedTag = data[readPosition:readPosition + 32]
            if len(requestedTag) != 32:
                return
            if requestedTag in shared.myAddressesByTag:
                myAddress = shared.myAddressesByTag[requestedTag]

        if myAddress == '':
            return

        if decodeAddress(myAddress)[1] != requestedAddressVersionNumber:
            return
        if decodeAddress(myAddress)[2] != streamNumber:
            return
        if shared.safeConfigGetBoolean(myAddress, 'chan'):
            return
        try:
            lastPubkeySendTime = int(shared.config.get(
                myAddress, 'lastpubkeysendtime'))
        except:
            lastPubkeySendTime = 0
        if lastPubkeySendTime > time.time() - 2419200:  # If the last time we sent our pubkey was more recent than 28 days ago...
            return
        if requestedAddressVersionNumber == 2:
            shared.workerQueue.put((
                'doPOWForMyV2Pubkey', requestedHash))
        elif requestedAddressVersionNumber == 3:
            shared.workerQueue.put((
                'sendOutOrStoreMyV3Pubkey', requestedHash))
        elif requestedAddressVersionNumber == 4:
            shared.workerQueue.put((
                'sendOutOrStoreMyV4Pubkey', myAddress))

    def processpubkey(self, data):
        pubkeyProcessingStartTime = time.time()
        shared.numberOfPubkeysProcessed += 1
        embeddedTime, = unpack('>Q', data[8:16])
        readPosition = 20  # bypass the nonce, time, and object type
        addressVersion, varintLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += varintLength
        streamNumber, varintLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += varintLength
        if addressVersion == 0:
            return
        if addressVersion > 4 or addressVersion == 1:
            return
        if addressVersion == 2:
            if len(data) < 146:  # sanity check. This is the minimum possible length.
                return
            bitfieldBehaviors = data[readPosition:readPosition + 4]
            readPosition += 4
            publicSigningKey = data[readPosition:readPosition + 64]
            # Is it possible for a public key to be invalid such that trying to
            # encrypt or sign with it will cause an error? If it is, it would
            # be easiest to test them here.
            readPosition += 64
            publicEncryptionKey = data[readPosition:readPosition + 64]
            if len(publicEncryptionKey) < 64:
                return
            readPosition += 64
            dataToStore = data[20:readPosition] # The data we'll store in the pubkeys table.
            sha = hashlib.new('sha512')
            sha.update(
                '\x04' + publicSigningKey + '\x04' + publicEncryptionKey)
            ripeHasher = hashlib.new('ripemd160')
            ripeHasher.update(sha.digest())
            ripe = ripeHasher.digest()

            address = encodeAddress(addressVersion, streamNumber, ripe)
            if address not in shared.hadPubkeys.keys():  # if this pubkey is already in our database and if we have used it personally:
                t = (address, addressVersion, dataToStore, int(time.time()), 'no')
		shared.hadPubkeys[address] = t
		shared.savePubkeyToFile()
		self.possibleNewPubkey(address)
                print "Received a pubkey for version 2 address:%s" % address
        if addressVersion == 3:
            if len(data) < 170:  # sanity check.
                return
            bitfieldBehaviors = data[readPosition:readPosition + 4]
            readPosition += 4
            publicSigningKey = '\x04' + data[readPosition:readPosition + 64]
            readPosition += 64
            publicEncryptionKey = '\x04' + data[readPosition:readPosition + 64]
            readPosition += 64
            specifiedNonceTrialsPerByte, specifiedNonceTrialsPerByteLength = decodeVarint(
                data[readPosition:readPosition + 10])
            readPosition += specifiedNonceTrialsPerByteLength
            specifiedPayloadLengthExtraBytes, specifiedPayloadLengthExtraBytesLength = decodeVarint(
                data[readPosition:readPosition + 10])
            readPosition += specifiedPayloadLengthExtraBytesLength
            endOfSignedDataPosition = readPosition
            dataToStore = data[20:readPosition] # The data we'll store in the pubkeys table.
            signatureLength, signatureLengthLength = decodeVarint(
                data[readPosition:readPosition + 10])
            readPosition += signatureLengthLength
            signature = data[readPosition:readPosition + signatureLength]
            if not highlevelcrypto.verify(data[8:endOfSignedDataPosition], signature, publicSigningKey.encode('hex')):
                return

            sha = hashlib.new('sha512')
            sha.update(publicSigningKey + publicEncryptionKey)
            ripeHasher = hashlib.new('ripemd160')
            ripeHasher.update(sha.digest())
            ripe = ripeHasher.digest()
            
            address = encodeAddress(addressVersion, streamNumber, ripe)
	    if address not in shared.hadPubkeys.keys():
                t = (address, addressVersion, dataToStore, int(time.time()), 'no')
	        shared.hadPubkeys[address] = t
	        shared.savePubkeyToFile()
	        self.possibleNewPubkey(address)
                print "Received a pubkey for version 3 address:%s" % address

        if addressVersion == 4:
            if len(data) < 350:  # sanity check.
                return

            tag = data[readPosition:readPosition + 32]
            if tag not in shared.neededPubkeys:
                return
            
            # Let us try to decrypt the pubkey
            toAddress, cryptorObject = shared.neededPubkeys[tag]
            if shared.decryptAndCheckPubkeyPayload(data, toAddress) == 'successful':
                # At this point we know that we have been waiting on this pubkey.
                # This function will command the workerThread to start work on
                # the messages that require it.
                self.possibleNewPubkey(toAddress)

        # Display timing data
        timeRequiredToProcessPubkey = time.time(
        ) - pubkeyProcessingStartTime
        

    def processmsg(self, data):
        messageProcessingStartTime = time.time()
        shared.numberOfMessagesProcessed += 1
        readPosition = 20 # bypass the nonce, time, and object type
        msgVersion, msgVersionLength = decodeVarint(data[readPosition:readPosition + 9])
        if msgVersion != 1:
            return
        readPosition += msgVersionLength
        
        streamNumberAsClaimedByMsg, streamNumberAsClaimedByMsgLength = decodeVarint(
            data[readPosition:readPosition + 9])
        readPosition += streamNumberAsClaimedByMsgLength
        inventoryHash = calculateInventoryHash(data)
        initialDecryptionSuccessful = False
        # Let's check whether this is a message acknowledgement bound for us.
        if data[-32:] in shared.ackdataForWhichImWatching:
            del shared.ackdataForWhichImWatching[data[-32:]]
            sqlExecute('UPDATE sent SET status=?, lastactiontime=? WHERE ackdata=?',
                       'ackreceived',
                       int(time.time()), 
                       data[-32:])
            return
        # This is not an acknowledgement bound for me. See if it is a message
        # bound for me by trying to decrypt it with my private keys.
        
        for key, cryptorObject in shared.myECCryptorObjects.items():
            try:
                decryptedData = cryptorObject.decrypt(data[readPosition:])
                toRipe = key  # This is the RIPE hash of my pubkeys. We need this below to compare to the destination_ripe included in the encrypted data.
                initialDecryptionSuccessful = True
                break
            except Exception as err:
                pass
        if not initialDecryptionSuccessful:
            # This is not a message bound for me.
            return
        # This is a message bound for me.
        toAddress = shared.myAddressesByHash[
            toRipe]  # Look up my address based on the RIPE hash.
        readPosition = 0
        sendersAddressVersionNumber, sendersAddressVersionNumberLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        readPosition += sendersAddressVersionNumberLength
        if sendersAddressVersionNumber == 0:
            return
        if sendersAddressVersionNumber > 4:
            return
        if len(decryptedData) < 170:
            return
        sendersStreamNumber, sendersStreamNumberLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        if sendersStreamNumber == 0:
            return
        readPosition += sendersStreamNumberLength
        behaviorBitfield = decryptedData[readPosition:readPosition + 4]
        readPosition += 4
        pubSigningKey = '\x04' + decryptedData[
            readPosition:readPosition + 64]
        readPosition += 64
        pubEncryptionKey = '\x04' + decryptedData[
            readPosition:readPosition + 64]
        readPosition += 64
        if sendersAddressVersionNumber >= 3:
            requiredAverageProofOfWorkNonceTrialsPerByte, varintLength = decodeVarint(
                decryptedData[readPosition:readPosition + 10])
            readPosition += varintLength
            requiredPayloadLengthExtraBytes, varintLength = decodeVarint(
                decryptedData[readPosition:readPosition + 10])
            readPosition += varintLength
        endOfThePublicKeyPosition = readPosition  # needed for when we store the pubkey in our database of pubkeys for later use.
        if toRipe != decryptedData[readPosition:readPosition + 20]:
            return
        readPosition += 20
        messageEncodingType, messageEncodingTypeLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        readPosition += messageEncodingTypeLength
        messageLength, messageLengthLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        readPosition += messageLengthLength
        message = decryptedData[readPosition:readPosition + messageLength]
        readPosition += messageLength
        ackLength, ackLengthLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        readPosition += ackLengthLength
        ackData = decryptedData[readPosition:readPosition + ackLength]
        readPosition += ackLength
        positionOfBottomOfAckData = readPosition  # needed to mark the end of what is covered by the signature
        signatureLength, signatureLengthLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        readPosition += signatureLengthLength
        signature = decryptedData[
            readPosition:readPosition + signatureLength]
        signedData = data[8:20] + encodeVarint(1) + encodeVarint(streamNumberAsClaimedByMsg) + decryptedData[:positionOfBottomOfAckData]
        
        if not highlevelcrypto.verify(signedData, signature, pubSigningKey.encode('hex')):
            return
        sigHash = hashlib.sha512(hashlib.sha512(signature).digest()).digest()[32:] # Used to detect and ignore duplicate messages in our inbox

        # calculate the fromRipe.
        sha = hashlib.new('sha512')
        sha.update(pubSigningKey + pubEncryptionKey)
        ripe = hashlib.new('ripemd160')
        ripe.update(sha.digest())
        fromAddress = encodeAddress(
            sendersAddressVersionNumber, sendersStreamNumber, ripe.digest())
        
        # Let's store the public key in case we want to reply to this
        # person.
        if fromAddress not in shared.hadPubkeys.keys():
            shared.hadPubkeys[fromAddress] = (fromAddress, sendersAddressVersionNumber, decryptedData[:endOfThePublicKeyPosition], int(time.time()), 'yes')
            shared.savePubkeyToFile()
            # Check to see whether we happen to be awaiting this
            # pubkey in order to send a message. If we are, it will do the POW
            # and send it.
            self.possibleNewPubkey(fromAddress)
            
        # If this message is bound for one of my version 3 addresses (or
        # higher), then we must check to make sure it meets our demanded
        # proof of work requirement. If this is bound for one of my chan
        # addresses then we skip this check; the minimum network POW is
        # fine.
        blockMessage = False  # Gets set to True if the user shouldn't see the message according to black or white lists.
        if shared.config.get('bitmessagesettings', 'blackwhitelist') == 'black':  # If we are using a blacklist
            if fromAddress in shared.blacklist:
                blockMessage = True
        else:  # We're using a whitelist
            if fromAddress not in shared.whitelist:
                blockMessage = True
        
        toLabel = shared.config.get(toAddress, 'label')
        if toLabel == '':
            toLabel = toAddress

        if messageEncodingType == 2:
            subject, body = self.decodeType2Message(message)
        elif messageEncodingType == 1:
            body = message
            subject = ''
        elif messageEncodingType == 0:
            subject = ''
            body = '' 
        else:
            body = 'Unknown encoding type.\n\n' + repr(message)
            subject = ''
        # Let us make sure that we haven't already received this message
        if messageEncodingType != 0:
            t = (inventoryHash, toAddress, fromAddress, subject, int(
                time.time()), body, 'inbox', messageEncodingType, 0, sigHash)
            if t not in shared.messages:
                shared.messages.append(t)

        if self.ackDataHasAVaildHeader(ackData):
            shared.checkAndShareObjectWithPeers(ackData[24:])

        # Display timing data
        timeRequiredToAttemptToDecryptMessage = time.time(
        ) - messageProcessingStartTime
        shared.successfullyDecryptMessageTimings.append(
            timeRequiredToAttemptToDecryptMessage)
        sum = 0
        for item in shared.successfullyDecryptMessageTimings:
            sum += item

    def possibleNewPubkey(self, address):
        """
        We have inserted a pubkey into our pubkey table which we received from a
        pubkey, msg, or broadcast message. It might be one that we have been
        waiting for. Let's check.
        """
        
        # For address versions <= 3, we wait on a key with the correct address version,
        # stream number, and RIPE hash.
        status, addressVersion, streamNumber, ripe = decodeAddress(address)
        if addressVersion <=3:
            if address in shared.neededPubkeys:
                del shared.neededPubkeys[address]
                self.sendMessages(address)
        # For address versions >= 4, we wait on a pubkey with the correct tag.
        # Let us create the tag from the address and see if we were waiting
        # for it.
        elif addressVersion >= 4:
            tag = hashlib.sha512(hashlib.sha512(encodeVarint(
                addressVersion) + encodeVarint(streamNumber) + ripe).digest()).digest()[32:]
            if tag in shared.neededPubkeys:
                del shared.neededPubkeys[tag]
                self.sendMessages(address)

    def sendMessages(self, address):
        """
        This function is called by the possibleNewPubkey function when
        that function sees that we now have the necessary pubkey
        to send one or more messages.
        """
        sqlExecute(
            '''UPDATE sent SET status='doingmsgpow', retrynumber=0 WHERE toaddress=? AND (status='awaitingpubkey' or status='doingpubkeypow') AND folder='sent' ''',
            address)
        shared.workerQueue.put(('sendmessage', ''))

    def ackDataHasAVaildHeader(self, ackData):
        if len(ackData) < shared.Header.size:
            return False
        
        magic,command,payloadLength,checksum = shared.Header.unpack(ackData[:shared.Header.size])
        if magic != 0xE9BEB4D9:
            return False
        payload = ackData[shared.Header.size:]
        if len(payload) != payloadLength:
            return False
        if payloadLength > 1600100: # ~1.6 MB which is the maximum possible size of an inv message.
            """
            The largest message should be either an inv or a getdata message at 1.6 MB in size. 
            That doesn't mean that the object may be that big. The 
            shared.checkAndShareObjectWithPeers function will verify that it is no larger than 
            2^18 bytes.
            """
            return False
        if checksum != hashlib.sha512(payload).digest()[0:4]:  # test the checksum in the message.
            return False
        command = command.rstrip('\x00')
        if command != 'object':
            return False
        return True

    def addMailingListNameToSubject(self, subject, mailingListName):
        subject = subject.strip()
        if subject[:3] == 'Re:' or subject[:3] == 'RE:':
            subject = subject[3:].strip()
        if '[' + mailingListName + ']' in subject:
            return subject
        else:
            return '[' + mailingListName + '] ' + subject

    def decodeType2Message(self, message):
        bodyPositionIndex = string.find(message, '\nBody:')
        if bodyPositionIndex > 1:
            subject = message[8:bodyPositionIndex]
            # Only save and show the first 500 characters of the subject.
            # Any more is probably an attack.
            subject = subject[:500]
            body = message[bodyPositionIndex + 6:]
        else:
            subject = ''
            body = message
        # Throw away any extra lines (headers) after the subject.
        if subject:
            subject = subject.splitlines()[0]
        return subject, body
