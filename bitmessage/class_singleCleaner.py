import threading
import shared
import time
import sys
import os
import pickle

#import tr#anslate
from helper_sql import *

"""
The singleCleaner class is a timer-driven thread that cleans data structures 
to free memory, resends messages when a remote node doesn't respond, and 
sends pong messages to keep connections alive if the network isn't busy.
It cleans these data structures in memory:
inventory (moves data to the on-disk sql database)
inventorySets (clears then reloads data out of sql database)

It cleans these tables on the disk:
inventory (clears expired objects)
pubkeys (clears pubkeys older than 4 weeks old which we have not used personally)

It resends messages when there has been no response:
resends getpubkey messages in 5 days (then 10 days, then 20 days, etc...)
resends msg messages in 5 days (then 10 days, then 20 days, etc...)

"""


class singleCleaner(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        timeWeLastClearedInventoryAndPubkeysTables = 0
        try:
            shared.maximumLengthOfTimeToBotherResendingMessages = (float(shared.config.get('bitmessagesettings', 'stopresendingafterxdays')) * 24 * 60 * 60) + (float(shared.config.get('bitmessagesettings', 'stopresendingafterxmonths')) * (60 * 60 * 24 *365)/12)
        except:
            # Either the user hasn't set stopresendingafterxdays and stopresendingafterxmonths yet or the options are missing from the config file.
            shared.maximumLengthOfTimeToBotherResendingMessages = float('inf')

        while True:
            with shared.inventoryLock: # If you use both the inventoryLock and the sqlLock, always use the inventoryLock OUTSIDE of the sqlLock.
                with SqlBulkExecute() as sql:
                    for hash, storedValue in shared.inventory.items():
                        objectType, streamNumber, payload, expiresTime, tag = storedValue
                        sql.execute(
                            '''INSERT INTO inventory VALUES (?,?,?,?,?,?)''',
                            hash,
                            objectType,
                            streamNumber,
                            payload,
                            expiresTime,
                            tag)
                        del shared.inventory[hash]
            
            shared.broadcastToSendDataQueues((
                0, 'pong', 'no data')) # commands the sendData threads to send out a pong message if they haven't sent anything else in the last five minutes. The socket timeout-time is 10 minutes.
            # If we are running as a daemon then we are going to fill up the UI
            # queue which will never be handled by a UI. We should clear it to
            # save memory.

            if timeWeLastClearedInventoryAndPubkeysTables < int(time.time()) - 7380:
                timeWeLastClearedInventoryAndPubkeysTables = int(time.time())
                sqlExecute(
                    '''DELETE FROM inventory WHERE expirestime<? ''',
                    int(time.time()) - (60 * 60 * 3))

                # Let us resend getpubkey objects if we have not yet heard a pubkey, and also msg objects if we have not yet heard an acknowledgement
                queryreturn = sqlQuery(
                    '''select toaddress, ackdata, status FROM sent WHERE ((status='awaitingpubkey' OR status='msgsent') AND folder='sent' AND sleeptill<? AND senttime>?) ''',
                    int(time.time()),
                    int(time.time()) - shared.maximumLengthOfTimeToBotherResendingMessages)
                for row in queryreturn:
                    if len(row) < 2:
                        time.sleep(3)
                        break
                    toAddress, ackData, status = row
                    if status == 'awaitingpubkey':
                        resendPubkeyRequest(toAddress)
                    elif status == 'msgsent':
                        resendMsg(ackData)

                # Let's also clear and reload shared.inventorySets to keep it from
                # taking up an unnecessary amount of memory.
                for streamNumber in shared.inventorySets:
                    shared.inventorySets[streamNumber] = set()
                    queryData = sqlQuery('''SELECT hash FROM inventory WHERE streamnumber=?''', streamNumber)
                    for row in queryData:
                        shared.inventorySets[streamNumber].add(row[0])
                with shared.inventoryLock:
                    for hash, storedValue in shared.inventory.items():
                        objectType, streamNumber, payload, expiresTime, tag = storedValue
                        if not streamNumber in shared.inventorySets:
                            shared.inventorySets[streamNumber] = set()
                        shared.inventorySets[streamNumber].add(hash)

            # Let us write out the knowNodes to disk if there is anything new to write out.
            if shared.needToWriteKnownNodesToDisk:
                shared.knownNodesLock.acquire()
                output = open(shared.appdata + 'knownnodes.dat', 'wb')
                try:
                    pickle.dump(shared.knownNodes, output)
                    output.close()
                except Exception as err:
                    if "Errno 28" in str(err):
                        os._exit(0)
                shared.knownNodesLock.release()
                shared.needToWriteKnownNodesToDisk = False
            time.sleep(300)


def resendPubkeyRequest(address):
    try:
        del shared.neededPubkeys[
            address] # We need to take this entry out of the shared.neededPubkeys structure because the shared.workerQueue checks to see whether the entry is already present and will not do the POW and send the message because it assumes that it has already done it recently.
    except:
        pass
    sqlExecute(
        '''UPDATE sent SET status='msgqueued' WHERE toaddress=?''',
        address)
    shared.workerQueue.put(('sendmessage', ''))

def resendMsg(ackdata):
    sqlExecute(
        '''UPDATE sent SET status='msgqueued' WHERE ackdata=?''',
        ackdata)
    shared.workerQueue.put(('sendmessage', ''))
