#!/usr/bin/python2

import bitmessage
import os
import time
import sys

bitmessage.start()
print "Bitmessage started..."
print "Your address is %s" % bitmessage.getCurrentAddress()
testaddr = 'BM-2cU1gvauGukBHXPCARmHqfvut2YMFmu8Ce'
while True:
    #Construct a message here
    now = time.strftime("%H:%M:%S %Z", time.localtime(time.time()))
    message = "Time:" + now + "\n"
    ackdata = bitmessage.sendMessage(testaddr, "Come with some test", message)
    print "Send system info at %s" % now
    time.sleep(10 * 60)
