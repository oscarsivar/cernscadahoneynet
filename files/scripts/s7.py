#!/usr/bin/env python

# s7.py
#
# Copyright (C) 2006  Joel Arnold - EPFL & CERN
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

import struct, math

class s7:

  def decode(self, raw_packet):
  	
    s7_fields = {}
    s7_fields['pdu_type'] = pdu_type = struct.unpack('B', raw_packet[1])[0]
    s7_fields['seq_nbr'] = seq_nbr = struct.unpack('>H', raw_packet[4:6])[0]	
  	
    if (pdu_type == 1):      	# REQUEST
      s7_fields['req_type'] = req_type = struct.unpack('B', raw_packet[10])[0]
  	
      if (req_type == 4):    	# READ REQUEST
        s7_fields['nb_read'] = nb_read = struct.unpack('B', raw_packet[11])[0]
        s7_fields['reads'] = []
        for i in range(0, nb_read):
          byte_count = struct.unpack('>H', raw_packet[16 + 12*i : 18 + 12*i])[0]
          source_id = struct.unpack('>H', raw_packet[18 + 12*i : 20 + 12*i])[0]
          source = struct.unpack('>H', raw_packet[20 + 12*i : 22 + 12*i])[0]
          address = struct.unpack('>H', raw_packet[22 + 12*i : 24 + 12*i])[0]
          s7_fields['reads'].append([ byte_count, source_id, source, address ])
    	
      elif (req_type == 5):    	# WRITE REQUEST
        s7_fields['nb_writes'] = nb_writes = struct.unpack('B', raw_packet[11])[0]
        s7_fields['writes'] = []
        pos = 12
        for i in range(0, nb_writes):
          pos += 4
          byte_count = struct.unpack('>H', raw_packet[pos : pos+2])[0]
          dest_id = struct.unpack('>H', raw_packet[pos+2 : pos+4])[0]
          dest = struct.unpack('>H', raw_packet[pos+4 : pos+6])[0]
          address = struct.unpack('>H', raw_packet[pos+6 : pos+8])[0]
          pos += 8
          s7_fields['writes'].append([byte_count, dest_id, dest, address])
        for i in range(0, nb_writes):
          pos += 4
          dlen = s7_fields['writes'][i][0]
          data = struct.unpack('B'*dlen, raw_packet[pos : pos+dlen])
          pos += dlen
          s7_fields['writes'][i].append(data)

      elif (req_type == 40):    	# CPU START REQUEST
        pass

      elif (req_type == 41):    	# CPU STOP REQUEST
        pass

      elif (req_type == 240):    	# PDU SIZE NEGOTIATION REQUEST
        s7_fields['data'] = raw_packet[10:16]
        s7_fields['max'] = struct.unpack('>H', raw_packet[16:18])[0]
    	
      else:
        pass
  	
    else:          	# NOT A REQUEST
      pass
  	
    return s7_fields

  def encode(self, s7_fields):
  	
    if (s7_fields['pdu_type'] == 3):  	# RESPONSE
    	
      if (s7_fields['req_type'] == 4):	# READ RESPONSE
        raw_packet = struct.pack('>' + 'B'*4 + 'HBB', 50, 3, 0, 0, s7_fields['seq_nbr'], 0, 2)
        length = s7_fields['nb_read'] * 4
        for read in s7_fields['reads']:
          if (read[0]/8) % 2 == 0:
            length += read[0]/8
          else:
            length += read[0]/8 + 1
            read[1] += struct.pack('B', 0)
        raw_packet += struct.pack('>HBBBB', length, 0, 0, 4, s7_fields['nb_read'])
        for read in s7_fields['reads']:
          if (read[0] == 0):
            raw_packet += read[1]
          else:
            raw_packet += struct.pack('BB', 255, 4)
            raw_packet += struct.pack('>H', read[0])
            raw_packet += read[1]

      elif (s7_fields['req_type'] == 5):	# WRITE RESPONSE
        raw_packet = struct.pack('>' + 'B'*4 + 'HBB', 50, 3, 0, 0, s7_fields['seq_nbr'], 0, 2)
        raw_packet += struct.pack('>HBBBB', s7_fields['nb_writes'], 0, 0, 5, s7_fields['nb_writes'])
        for write in s7_fields['writes']:
          raw_packet += struct.pack('B', write)

      elif (s7_fields['req_type'] == 40):	# CPU START RESPONSE
        raw_packet = struct.pack('>BBBBHBBBBBBB', 50, 3, 0, 0, s7_fields['seq_nbr'], 0, 1, 0, 0, 0, 0, s7_fields['req_type'])
    	
      elif (s7_fields['req_type'] == 41):	# CPU STOP RESPONSE
        raw_packet = struct.pack('>BBBBHBBBBBBB', 50, 3, 0, 0, s7_fields['seq_nbr'], 0, 1, 0, 0, 0, 0, s7_fields['req_type'])
    	
      elif (s7_fields['req_type'] == 240):	# PDU SIZE NEGOTIATION RESPONSE
        raw_packet = struct.pack('>' + 'B'*4 + 'H' + 'B'*6, 50, 3, 0, 0, s7_fields['seq_nbr'], 0, 8, 0, 0, 0, 0)
        raw_packet += s7_fields['data']
        raw_packet += struct.pack('>H', s7_fields['max'])
      else:
        pass

    else:          	# NOT A RESPONSE
      pass
  	
    return raw_packet
