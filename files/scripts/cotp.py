#!/usr/bin/env python

# cotp.py
#
# Copyright (C) 2006  Joel Arnold - EPFL & CERN
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

import struct, math

class cotp:

  def decode(self, raw_packet):
    length = struct.unpack('B', raw_packet[0])[0]
    cotp_fields = { 'length' : length }
    code = struct.unpack('B', raw_packet[1])[0]/16
    if (code == 14):
      type = 'CR'
      cotp_fields['type'] = type
      dst_ref = struct.unpack('!H', raw_packet[2:4])[0]
      cotp_fields['dst_ref'] = dst_ref
      src_ref = struct.unpack('!H', raw_packet[4:6])[0]
      cotp_fields['src_ref'] = src_ref
      cla_opt = struct.unpack('B', raw_packet[6])[0]
      cotp_fields['cla_opt'] = cla_opt
      if ((length - 6) > 0):
        pos = 7
        while (pos < (1+length)):
          param_code = struct.unpack('B', raw_packet[pos])[0]
          pos += 1
          if (param_code == 193):
            pos += 1
            calling_tsap = struct.unpack('!H', raw_packet[pos:(pos+2)])[0]
            pos += 2
            cotp_fields['calling_tsap'] = calling_tsap
          elif (param_code == 194):
            pos += 1
            called_tsap = struct.unpack('!H', raw_packet[pos:(pos+2)])[0]
            pos += 2
            cotp_fields['called_tsap'] = called_tsap
          elif (param_code == 192):
            pos += 1
            pdu_length = struct.unpack('B', raw_packet[pos])[0]
            pos += 1
            cotp_fields['pdu_length'] = pdu_length
          else:
            break
      
    elif (code == 13):
      type = 'CC'
      cotp_fields['type'] = type
    elif (code == 8):
      type = 'DR'
      cotp_fields['type'] = type
    elif (code == 12):
      type = 'DC'
      cotp_fields['type'] = type
    elif (code == 15):
      type = 'DT'
      cotp_fields['type'] = type
      eot_nr = struct.unpack('B', raw_packet[2])[0]
      eot = eot_nr / 128
      cotp_fields['eot'] = eot
      seq_nbr = eot_nr % 128
      cotp_fields['seq_nbr'] = seq_nbr
      data = raw_packet[3:]
      cotp_fields['data'] = data
    elif (code == 1):
      type = 'ED'
      cotp_fields['type'] = type
    elif (code == 6):
      type = 'AK'
      cotp_fields['type'] = type
    elif (code == 2):
      type = 'EA'
      cotp_fields['type'] = type
    elif (code == 5):
      type = 'RJ'
      cotp_fields['type'] = type
    elif (code == 7):
      type = 'ER'
      cotp_fields['type'] = type
    else:
      type = 'NA'
      cotp_fields['type'] = type
    
    return cotp_fields
  
  def encode(self, cotp_fields):
    if (cotp_fields['type'] == 'CC'):
      raw_packet = struct.pack('B', cotp_fields['length'])
      raw_packet += struct.pack('B', 13*16)
      raw_packet += struct.pack('!H', cotp_fields['dst_ref'])
      raw_packet += struct.pack('!H', cotp_fields['src_ref'])
      raw_packet += struct.pack('B', cotp_fields['cla_opt'])
      if ('pdu_length' in cotp_fields):
        raw_packet += struct.pack('B', 192)
        raw_packet += struct.pack('B', 1)
        raw_packet += struct.pack('B', cotp_fields['pdu_length'])
      if ('calling_tsap' in cotp_fields):
        raw_packet += struct.pack('B', 193)
        raw_packet += struct.pack('B', 2)
        raw_packet += struct.pack('!H', cotp_fields['calling_tsap'])
      if ('called_tsap' in cotp_fields):
        raw_packet += struct.pack('B', 194)
        raw_packet += struct.pack('B', 2)
        raw_packet += struct.pack('!H', cotp_fields['called_tsap'])
    elif (cotp_fields['type'] == 'DT'):
      raw_packet = struct.pack('BBB', 2, 240, 128) + cotp_fields['data']
    return raw_packet
