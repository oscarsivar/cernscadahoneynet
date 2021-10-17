#!/usr/bin/env python

import socket, struct, tpkt, cotp, logging, s7, math
from memory import memory

logging.basicConfig(level=logging.DEBUG)

HOST = ''
PORT = 102

def receive_packet(connection):
	tpkt_data = connection.recv(4)
	if (tpkt_data == ''):
		logging.debug("\tReceived nothing...")
		return ''
	else:
		logging.debug("\tReceiving packet :: " + repr(tpkt_data))
		tpkt_fields = tpkt.tpkt().decode(tpkt_data)
		cotp_data = connection.recv(tpkt_fields['length'])
		logging.debug("\tReceiving packet :: " + repr(cotp_data))
		return cotp.cotp().decode(cotp_data)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)

while True:
	conn, addr = s.accept()
	logging.debug("\tConnected to " + str(addr[0]))

	while True:
		logging.debug("\tReady to receive data")
		cotp_fields = receive_packet(conn)
		
		if (cotp_fields == ''):
			break
	
		elif (cotp_fields['type'] == 'CR'):		# CONNECTION REQUEST
			# Prepare a connection confirm packet
			cotp_fields['type'] = 'CC'
			cotp_fields['dst_ref'] = cotp_fields['src_ref']
			cotp_fields['src_ref'] = 17457
			cotp_data = cotp.cotp().encode(cotp_fields)
			tpkt_data = tpkt.tpkt().encode(cotp_data)
			# Send it
			logging.debug("\tSending packet   :: " + repr(tpkt_data))
			conn.send(tpkt_data)

			# Prepare a pdu size negotiation packet
			#s7_fields = { 	'pdu_type' : 3,
			#		'seq_nbr' : 65535,
			#		'req_type' : 240,
			#		'data' : struct.pack('B'*6, 240, 0, 0, 1, 0, 1),
			#		'max' : 240	}
			#
			#cotp_fields = { 'type' : 'DT' }
			#cotp_fields['data'] = s7.s7().encode(s7_fields)
			#cotp_data = cotp.cotp().encode(cotp_fields)
			#tpkt_data = tpkt.tpkt().encode(cotp_data)
			#
			#logging.debug("\tSending packet   :: " + repr(tpkt_data))
			#conn.send(tpkt_data)
			
			
		elif (cotp_fields['type'] == 'DT'):		# DATA
			s7_fields = s7.s7().decode(cotp_fields['data'])
			logging.debug("\tS7        : " + repr(s7_fields))
			
			if (s7_fields['req_type'] == 240):	# PDU SIZE NEGOTIATION
				s7_fields['pdu_type'] = 3
				s7_fields['max'] = min(240, s7_fields['max'])
				# Prepare a pdu size negotiation packet
				#s7_fields = { 	'pdu_type' : 3,
				#		'seq_nbr' : 65535,
				#		'req_type' : 240,
				#		'data' : struct.pack('B'*6, 240, 0, 0, 1, 0, 1),
				#		'max' : 240	}
				
				cotp_fields = { 'type' : 'DT' }
				cotp_fields['data'] = s7.s7().encode(s7_fields)
				cotp_data = cotp.cotp().encode(cotp_fields)
				tpkt_data = tpkt.tpkt().encode(cotp_data)
				
				logging.debug("\tSending packet   :: " + repr(tpkt_data))
				conn.send(tpkt_data)
				
			elif(s7_fields['req_type'] == 4):	# READ REQUEST
				
				read_reqs = s7_fields['reads']
				
				s7_fields = {
					'pdu_type'	:	3,
					'seq_nbr'	:	s7_fields['seq_nbr'],
					'req_type'	:	4,
					'nb_read'	:	s7_fields['nb_read']
					}
				
				s7_fields['reads'] = []
				
				for i in range(0, s7_fields['nb_read']):
					byte_count = read_reqs[i][0]
					source_id = read_reqs[i][1]
					source = read_reqs[i][2]
					address = read_reqs[i][3]
					if (not memory.has_key(source)):
						#not available
						bit_count = 0
						data = struct.pack('BBBB', 10, 0, 0, 0)
						s7_fields['reads'].append([bit_count, data])
					elif (source == 33792):
						if (not memory[source].has_key(source_id)):
							#not available
							bit_count = 0
							data = struct.pack('BBBB', 10, 0, 0, 0)
							s7_fields['reads'].append([bit_count, data])
						elif (address + byte_count > len(memory[source][source_id])):
							#out of range
							bit_count = 0
							data = struct.pack('BBBB', 5, 0, 0, 0)
							s7_fields['reads'].append([bit_count, data])
						else:
							#set the data accordingly
							bit_count = byte_count * 8
							data = ''
							for j in range(0, byte_count):
								data += struct.pack('B', memory[source][source_id][address + j])
							s7_fields['reads'].append([bit_count, data])
					elif (address + byte_count > len(memory[source])):
						#out of range
						bit_count = 0
						data = struct.pack('BBBB', 5, 0, 0, 0)
						s7_fields['reads'].append([bit_count, data])
					else:
						#set the data accordingly
						bit_count = byte_count * 8
						data = ''
						for j in range(0, byte_count):
							data += struct.pack('B', memory[source][address + j])
						s7_fields['reads'].append([bit_count, data])
				
				cotp_fields = { 'type' : 'DT' }
				cotp_fields['data'] = s7.s7().encode(s7_fields)
				cotp_data = cotp.cotp().encode(cotp_fields)
				tpkt_data = tpkt.tpkt().encode(cotp_data)
				
				logging.debug("\tSending packet   :: " + repr(tpkt_data))
				conn.send(tpkt_data)

			elif(s7_fields['req_type'] == 5):	# WRITE REQUEST
				write_reqs = s7_fields['writes']
				s7_fields = {
					'pdu_type'	:	3,
					'seq_nbr'	:	s7_fields['seq_nbr'],
					'req_type'	:	5,
					'nb_writes'	:	s7_fields['nb_writes']
					}
				s7_fields['writes'] = []
				for req in write_reqs:
					s7_fields['writes'].append(255)
				
				cotp_fields = { 'type' : 'DT' }
				cotp_fields['data'] = s7.s7().encode(s7_fields)
				cotp_data = cotp.cotp().encode(cotp_fields)
				tpkt_data = tpkt.tpkt().encode(cotp_data)
				
				logging.debug("\tSending packet   :: " + repr(tpkt_data))
				conn.send(tpkt_data)

			elif(s7_fields['req_type'] == 40):	# CPU START REQUEST
				s7_fields = {
					'pdu_type'	:	3,
					'seq_nbr'	:	s7_fields['seq_nbr'],
					'req_type'	:	s7_fields['req_type']
					}
				cotp_fields = { 'type' : 'DT' }
				cotp_fields['data'] = s7.s7().encode(s7_fields)
				cotp_data = cotp.cotp().encode(cotp_fields)
				tpkt_data = tpkt.tpkt().encode(cotp_data)
				
				logging.debug("\tSending packet   :: " + repr(tpkt_data))
				conn.send(tpkt_data)
				
			
			elif(s7_fields['req_type'] == 41):	# CPU START REQUEST
				s7_fields = {
					'pdu_type'	:	3,
					'seq_nbr'	:	s7_fields['seq_nbr'],
					'req_type'	:	s7_fields['req_type']
					}
				cotp_fields = { 'type' : 'DT' }
				cotp_fields['data'] = s7.s7().encode(s7_fields)
				cotp_data = cotp.cotp().encode(cotp_fields)
				tpkt_data = tpkt.tpkt().encode(cotp_data)
				
				logging.debug("\tSending packet   :: " + repr(tpkt_data))
				conn.send(tpkt_data)
			
			else:
				logging.debug("Unknown S7 request")
			
			
	logging.debug("\tClosing connection\n")
	conn.close()
