#!/usr/bin/env pyhton2.7

import bitmessage
import time

bitmessage.start()
print "Bitmessage started..."
print "Your address is %s" % bitmessage.getCurrentAddress()
testaddr = 'BM-2cU1gvauGukBHXPCARmHqfvut2YMFmu8Ce'
while True:
    now = time.strftime("%H:%M:%S %Z", time.localtime(time.time()))
    print now
    message = "Time:" + now + "\n"
    ackdata = bitmessage.sendMessage(testaddr, "Come with some test", message)
    time.sleep(10 * 60)
