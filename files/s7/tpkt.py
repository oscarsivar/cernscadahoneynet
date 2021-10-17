#!/usr/bin/env python

import struct

class tpkt:

	def decode(self, raw_packet):
		tpkt_fields = {
			'version'	: struct.unpack('B', raw_packet[0])[0],
			'reserved'	: struct.unpack('B', raw_packet[1])[0],
			'length'	: struct.unpack('!H', raw_packet[2:4])[0]
			}
		return tpkt_fields
	
	def encode(self, data):
		tpkt_data = struct.pack('!BBH', 3, 0, len(data) + 4) + data
		return tpkt_data
