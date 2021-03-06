# Copyright (c) 2012 Jonathan Warren
# Copyright (c) 2012 The Bitmessage developers
# Distributed under the MIT/X11 software license. See the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Right now, PyBitmessage only support connecting to stream 1. It doesn't
# yet contain logic to expand into further streams.

# The software version variable is now held in shared.py

import signal  # Used to capture a Ctrl-C keypress so that Bitmessage can shutdown gracefully.
import time

import shared
import threading

import addresses
from pyelliptic.openssl import OpenSSL

from winsockfix import _fixWinsock

# Classes
from class_sqlThread import sqlThread
from class_singleCleaner import singleCleaner
from class_objectProcessor import objectProcessor
from class_outgoingSynSender import outgoingSynSender
from class_singleListener import singleListener
from class_singleWorker import singleWorker
from class_addressGenerator import addressGenerator

# Helper Functions
import helper_bootstrap
import helper_generic
import helper_startup
import helper_sent
from helper_startup import isOurOperatingSystemLimitedToHavingVeryFewHalfOpenConnections
from helper_sql import sqlQuery
from helper_sql import sqlExecute
    

# This is a list of current connections (the thread pointers at least)
selfInitiatedConnections = {}

#Initilise bitmessage library
def start():
    # Create socket function that some versoin of python does not implement
    _fixWinsock()

    # Bind signal to default so that we can use Ctrl+C to stop it
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # Load known nodes
    helper_bootstrap.knownNodes()

    # Load config
    helper_startup.loadConfig()
    helper_startup.loadPubkeys()

    # Start the thread that ... I don't know.
    singleWorkerThread = singleWorker()
    singleWorkerThread.daemon = True  # close the main program even if there are threads left
    singleWorkerThread.start()

    # Start the SQL thread
    sqlLookup = sqlThread()
    sqlLookup.daemon = False  # DON'T close the main program even if there are threads left. The closeEvent should command this thread to exit gracefully.
    sqlLookup.start()

    # Start the thread that process object
    objectProcessorThread = objectProcessor()
    objectProcessorThread.daemon = False  # DON'T close the main program even the thread remains. This thread checks the shutdown variable after processing each object.
    objectProcessorThread.start()

    # Start the cleanerThread
    singleCleanerThread = singleCleaner()
    singleCleanerThread.daemon = True  # close the main program even if there are threads left
    singleCleanerThread.start()
    
    # Load my address
    shared.reloadMyAddressHashes()
    
    # Connect to the root stream 
    streamNumber = 1
    shared.streamsInWhichIAmParticipating[streamNumber] = 'no data'
    selfInitiatedConnections[streamNumber] = {}
    shared.inventorySets[streamNumber] = set() #We may write some codes below to initialise the set.

    if isOurOperatingSystemLimitedToHavingVeryFewHalfOpenConnections():
        maximumNumberOfHalfOpenConnections = 9
    else:
        maximumNumberOfHalfOpenConnections = 64
    for i in xrange(maximumNumberOfHalfOpenConnections):
        a = outgoingSynSender()
        a.setup(streamNumber, selfInitiatedConnections)
        a.start()

    # Start the singleListenerThread
    singleListenerThread = singleListener()
    singleListenerThread.setup(selfInitiatedConnections)
    singleListenerThread.daemon = True  # close the main program even if there are threads left
    singleListenerThread.start()

# Shutdown bitmessage library
def stop():
    shared.doCleanShutdown()

# Create a new address to send message and replace old
def generateNewAddress():
    # Start the address generating thread
    addressGeneratorThread = addressGenerator()
    addressGeneratorThread.daemon = True  # close the main program even if there are threads left
    addressGeneratorThread.start()
    # Check if we have addresses already
    if not len(shared.myAddressesByTag) == 0:
        for tag in shared.myAddressesByTag.keys():
            shared.config.remove_section(shared.myAddressesByTag[tag])
        shared.writeKeysFile()
    #Create address
    label = "BitMessage"
    eighteenByteRipe = False
    nonceTrialsPerByte = shared.config.get('bitmessagesettings', 'defaultnoncetrialsperbyte')
    payloadLengthExtraBytes = shared.config.get('bitmessagesettings', 'defaultpayloadlengthextrabytes')
    shared.addressGeneratorQueue.put(('createRandomAddress', 4, 1, "", eighteenByteRipe, nonceTrialsPerByte, payloadLengthExtraBytes))
    newaddr =  shared.apiAddressGeneratorReturnQueue.get()
    shared.addressGeneratorQueue.put(('exit',))
    addressGeneratorThread.join()
    return newaddr


# Get current bitmessage address which is used to send message
def getCurrentAddress():
    if not len(shared.myAddressesByTag.keys()) == 0:
        return shared.myAddressesByTag[shared.myAddressesByTag.keys()[0]]
    else:
        return generateNewAddress()


# Get incomming message
def getMessage():
    while len(shared.messages) == 0:
        time.sleep(1)
    t = shared.messages.pop()
    ret = {}
    ret['from'] = t[2]
    ret['subject'] = t[3]
    ret['message'] = t[5]
    ret['time'] = t[4]
    return ret

# Send message 
def sendMessage(toAddress, subject, message):
    if len(shared.myAddressesByTag) == 0:
        generateNewAddress()

    fromAddress = getCurrentAddress()
    status, addressVersionNumber, streamNumber, toRipe = addresses.decodeAddress(toAddress)
    ackdata = OpenSSL.rand(32)
    TTL = 4*24*60*60
    t = ('', toAddress, toRipe, fromAddress, subject, message, ackdata, int(time.time()), int(time.time()), 0, 'msgqueued', 0, 'sent', 2, TTL)
    helper_sent.insert(t)
    shared.workerQueue.put(('sendmessage', toAddress))

    return ackdata

# Get sending message status
def getStatusByAck(ackdata):
    query = sqlQuery("SELECT status FROM sent WHERE ackdata=? LIMIT 0,1", ackdata)
    if not len(query) == 0:
        return query[0][0]
    else:
        return "not found"


# set blacklist
def setBlacklist(address, operation):
    if operation == "set":
        if address not in shared.blacklist:
            shared.blacklist.append(address)
    elif operation == "unset":
        if address in shared.blacklist:
            shared.blacklist.remove(address)
    else:
        print "setBlacklist:Unsupported operation"

# set whitelist
def setWhitelist(address, operation):
    if operation == "set":
        if address not in shared.whitelist:
            shared.whitelist.append(address)
    elif operation == "unset":
        if address in shared.whitelist:
            shared.whitelist.remove(address)
    else:
        print "setWhitelist:Unsupported operation"

