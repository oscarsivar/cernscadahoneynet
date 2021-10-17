#!/usr/bin/env python 

# honeyd-http-schneider.py
#
# Copyright (C) 2006  Joel Arnold - EPFL & CERN
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

import re, sys, time, os

class HTTPSim:
  def run(self):
    while True:
      try:
        self.parseInput()
      except:
        sys.exit(0)

  def parseInput(self):
  	
    datestr = time.strftime("Date: %a, %d %b %Y %H:%M:%S GMT\r", time.gmtime(time.time()))
    close = True
    firstlinestr = '(\S*)\s*(\S*)\s*HTTP/(\d\.\d)'
    firstlinere = re.compile(firstlinestr)
    headerlinestr = '(\S*)\s*:\s*(\S*)'
    headerlinere = re.compile(headerlinestr)
    requestlines = []
    requestline = sys.stdin.readline()
    if (requestline == "\n" or requestline == "\r\n" or requestline == ""):
      return
    try:
      (method, path, version) = firstlinere.findall(requestline)[0]
    except:
      print "<TITLE>400 Bad Request</TITLE><BODY><P><H2>Bad Request.</H2><P><H3>Your browser sent a query that this server could not understand.</H3></BODY>\r"
      close = True
    else:
      if (version != '1.0' and version != '1.1'):
        print "HTTP/" + version + " 505 HTTP Version not supported.\r"
        print datestr
        print "Connection: close\r"
        close = True
        print "Content-Type: text/html\r"
        print "\r"
        print "<TITLE>505 HTTP Version not supported.</TITLE><BODY>505 HTTP Version not supported.</BODY>\r"
      elif (method != 'GET'):
        if (method in ['HEAD', 'PUT', 'POST', 'CONNECT', 'DELETE']):
          print "HTTP/" + version + " 405 Method Not Allowed\r"
          print datestr
          print "Connection: close\r"
          close = True
          print "Content-Type: text/html\r"
          print "\r"
          print "<TITLE>405 Method Not Allowed</TITLE><BODY>405 Method Not Allowed</BODY>\r"
        else:
          print "HTTP/" + version + " 501 Not Implemented\r"
          print datestr
          print "Connection: close\r"
          close = True
          print "Content-Type: text/html\r"
          print ""
          print "<TITLE>501 Not Implemented</TITLE><BODY>501 Not Implemented</BODY>\r"
      else:
        while (requestline not in ["\n", "\r\n", ""]):
          requestlines.append(requestline)
          requestline = sys.stdin.readline()
        headers = []
        for i in range(1, len(requestlines)):
          headers.append(headerlinere.findall(requestlines[i])[0])
        close = True
        for i in range(0, len(headers)):
          if (headers[i] == ('Connection', 'Keep-Alive')):
            close = False
        if (path.startswith('/')):
          npath = path[1:]
        npath = re.sub("\.+", ".", npath)
        npath = re.sub("(\./)+", "./", npath) 
        slashre = re.compile("/")
        spath = slashre.split(npath)
        fpath = spath[-1:][0]
        if (fpath == ""):
          fpath = "index.htm"
        dpath = '/'.join(spath[:-1])
        if (dpath.startswith('secure') or dpath.startswith('./secure')):
          print "HTTP/" + version + " 401 Unauthorized\r"
          print datestr
          if (close):
            print "Connection: close\r"
          else:
            print "Connection: Keep-Alive\r"
          close = True
          print "WWW-Authenticate: Basic realm=\"ETY_security\"\r"
          print "Content-Type: text/html\r"
          print "\r"
          print "<TITLE>401 Unauthorized</TITLE><BODY>401 Unauthorized</BODY>\r" 
        elif (fpath in os.listdir("/var/cshoneynet/scripts/web-schneider/" + dpath)):
          if (dpath != ""):
            dpath += "/"
          f = file("/var/cshoneynet/scripts/web-schneider/" + dpath + fpath, 'r')
          filelines = f.readlines()
          f.close()
          print "HTTP/" + version + " 200 Okay\r"
          print datestr
          if (close):
            print "Connection: close\r"
          else:
            print "Connection: Keep-Alive\r"
          length = 0
          for line in filelines:
            length += len(line)
          print "Content-Length: " + str(length) + "\r"
          print "Server: DECORUM/2.0\r"
          if (fpath.endswith('.gif')):
            print "Content-Type: image/gif\r"
          else:
            print "Content-Type: text/html\r"
          print "\r"
          for fileline in filelines:
            sys.stdout.write(fileline)
          sys.stdout.flush()
        else:
          print "HTTP/" + version + " 404 Not Found\r"
          print datestr
          if (close):
            print "Connection: close\r"
          else:
            print "Connection: Keep-Alive\r"
          close = True
          print "Content-Type: text/html\r"
          print "\r"
          print "<TITLE>404 Not Found</TITLE><BODY>404 Not Found</BODY>\r"
    if (close == True):
      sys.exit(0)

HTTPSim().run()
