import threading
import shared
import sqlite3
import time
import shutil  # used for moving the messages.dat file
import sys
import os
import random

# This thread exists because SQLITE3 is so un-threadsafe that we must
# submit queries to it and it puts results back in a different queue. They
# won't let us just use locks.


class sqlThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):        
        self.conn = sqlite3.connect(':memory:')
        self.conn.text_factory = str
        self.cur = self.conn.cursor()

        try:
            self.cur.execute(
                '''CREATE TABLE sent (msgid blob, toaddress text, toripe blob, fromaddress text, subject text, message text, ackdata blob, senttime integer, lastactiontime integer, sleeptill integer, status text, retrynumber integer, folder text, encodingtype int, ttl int)''' )
            self.cur.execute(
                '''CREATE TABLE subscriptions (label text, address text, enabled bool)''' )
            self.cur.execute(
                '''CREATE TABLE addressbook (label text, address text)''' )
            self.cur.execute(
                '''CREATE TABLE blacklist (label text, address text, enabled bool)''' )
            self.cur.execute(
                '''CREATE TABLE whitelist (label text, address text, enabled bool)''' )
            self.cur.execute(
                '''CREATE TABLE inventory (hash blob, objecttype int, streamnumber int, payload blob, expirestime integer, tag blob, UNIQUE(hash) ON CONFLICT REPLACE)''' )
            self.cur.execute(
                '''INSERT INTO subscriptions VALUES('Bitmessage new releases/announcements','BM-GtovgYdgs7qXPkoYaRgrLFuFKz1SFpsw',1)''')
            self.cur.execute(
                '''CREATE TABLE settings (key blob, value blob, UNIQUE(key) ON CONFLICT REPLACE)''' )
            self.cur.execute( '''INSERT INTO settings VALUES('version','10')''')
            self.cur.execute( '''INSERT INTO settings VALUES('lastvacuumtime',?)''', (
                int(time.time()),))
            self.cur.execute(
                '''CREATE TABLE objectprocessorqueue (objecttype int, data blob, UNIQUE(objecttype, data) ON CONFLICT REPLACE)''' )
            self.conn.commit()
        except Exception as err:
            sys.stderr.write(
                'ERROR trying to create database file (message.dat). Error message: %s\n' % str(err))
            os._exit(0)

        while True:
            item = shared.sqlSubmitQueue.get()
            if item == 'commit':
                try:
                    self.conn.commit()
                except Exception as err:
                    print "1" + str(err)
                    if str(err) == 'database or disk is full':
                        os._exit(0)
            elif item == 'exit':
                self.conn.close()

                return
            elif item == 'movemessagstoprog':

                try:
                    self.conn.commit()
                except Exception as err:
                    print "2" + str(err)
                    if str(err) == 'database or disk is full':
                        os._exit(0)
                self.conn.close()
                shutil.move(
                    shared.lookupAppdataFolder() + 'messages.dat', 'messages.dat')
                self.conn = sqlite3.connect('messages.dat')
                self.conn.text_factory = str
                self.cur = self.conn.cursor()
            elif item == 'movemessagstoappdata':

                try:
                    self.conn.commit()
                except Exception as err:
                    print "3" + str(err)
                    if str(err) == 'database or disk is full':
                        os._exit(0)
                self.conn.close()
                shutil.move(
                    'messages.dat', shared.lookupAppdataFolder() + 'messages.dat')
                self.conn = sqlite3.connect(shared.appdata + 'messages.dat')
                self.conn.text_factory = str
                self.cur = self.conn.cursor()
            elif item == 'deleteandvacuume':
                self.cur.execute('''delete from sent where folder='trash' ''')
                self.conn.commit()
                try:
                    self.cur.execute( ''' VACUUM ''')
                except Exception as err:
                    print "4" + str(err)
                    if str(err) == 'database or disk is full':
                        os._exit(0)
            else:
                parameters = shared.sqlSubmitQueue.get()
                try:
                    self.cur.execute(item, parameters)
                except Exception as err:
                    print "5" + str(err)
                    print "Query:"
                    print item
                    print parameters
                    if str(err) == 'database or disk is full':
                        os._exit(0)
                    else:
                        pass
                    os._exit(0)

                shared.sqlReturnQueue.put(self.cur.fetchall())
                # shared.sqlSubmitQueue.task_done()
