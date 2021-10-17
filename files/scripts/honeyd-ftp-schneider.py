#!/usr/bin/env python 

# honeyd-ftp-schneider.py
#
# Copyright (C) 2006  Joel Arnold - EPFL & CERN
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

import re, sys, signal

inittext = "220 VxWorks FTP server (VxWorks 5.4) ready.\r\n"
helptext = "214-The following commands are recognized:\r\nHELP\tUSER\tPASS\tQUIT\tLIST\tNLST\tFREE\nRETR\tSTOR\tCWD\tTYPE\tPORT\tPWD\tFORMAT\nSTRU\tMODE\tALLO\tACCT\tPASV\tNOOP\nDELE\tRNFR\tRNTO\tMKD\tRMD\tMDTM\nSIZE\tSYST\tXCWD\tXPWD\tXMKD\tXRMD\n214 End of command list.\r\n"
passtext = "530 Login failed.\r\n"
quittext = "221 Bye...see you later\r\n"
systtext = "215 UNIX Type: L8 Version: VxWorks\r\n"
usertext = "331 Password required\r\n"
elsetext = "530 USER and PASS required\r\n"

class FTPSim:

  def run(self):
    sys.stdout.write(inittext)
    sys.stdout.flush()
    while True:
      try:
        self.parseInput()
      except:
        sys.exit(0)

  def parseInput(self):
    close = False
    def sighandler(signum, frame):
      sys.exit(0)
    signal.signal(signal.SIGALRM, sighandler)
    signal.alarm(100)
    requestline = sys.stdin.readline()
    signal.alarm(0)
    if (requestline == "\n" or requestline == "\r\n"):
      return
    if (requestline == ""):
      sys.exit(0)
    requestparser = re.compile('(\S{4})(.*)')
    try:
      (method, args) = requestparser.match(requestline.strip()).groups()
      method = method.upper()
      if method.startswith('HELP'):
        sys.stdout.write(helptext)
        sys.stdout.flush()
      elif method.startswith('PASS'):
        sys.stdout.write(passtext)
        sys.stdout.flush()
      elif method.startswith('QUIT'):
        sys.stdout.write(quittext)
        sys.stdout.flush()
        close = True
      elif method.startswith('SYST'):
        sys.stdout.write(systtext)
        sys.stdout.flush()
      elif method.startswith('USER'):
        sys.stdout.write(usertext)
        sys.stdout.flush()
      else:
        sys.stdout.write(elsetext)
        sys.stdout.flush()
    except:
      sys.stdout.write(elsetext)
      sys.stdout.flush()

    if (close == True):
      sys.exit(0)

FTPSim().run()
