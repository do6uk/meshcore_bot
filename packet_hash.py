import hashlib

def calculate_packet_hash(raw_hex: str, payload_type: int = None) -> str:
	"""Calculate hash for packet identification - based on packet.cpp"""
	try:
		# Parse the packet to extract payload type and payload data
		byte_data = bytes.fromhex(raw_hex)
		header = byte_data[0]
		
		# Get payload type from header (bits 2-5)
		if payload_type is None:
			payload_type = (header >> 2) & 0x0F
		
		# Check if transport codes are present
		route_type = header & 0x03
		has_transport = route_type in [0x00, 0x03]  # TRANSPORT_FLOOD or TRANSPORT_DIRECT
		
		# Calculate path length offset dynamically based on transport codes
		offset = 1  # After header
		if has_transport:
			offset += 4  # Skip 4 bytes of transport codes
		
		# Read path_len (1 byte on wire, but stored as uint16_t in C++)
		path_len = byte_data[offset]
		offset += 1
		
		# Skip past the path to get to payload
		payload_start = offset + path_len
		payload_data = byte_data[payload_start:]
		
		# Calculate hash exactly like MeshCore Packet::calculatePacketHash():
		# 1. Payload type (1 byte)
		# 2. Path length (2 bytes as uint16_t, little-endian) - ONLY for TRACE packets (type 9)
		# 3. Payload data
		hash_obj = hashlib.sha256()
		hash_obj.update(bytes([payload_type]))
		
		if payload_type == 9:  # PAYLOAD_TYPE_TRACE
			# C++ does: sha.update(&path_len, sizeof(path_len))
			# path_len is uint16_t, so sizeof(path_len) = 2 bytes
			# Convert path_len to 2-byte little-endian uint16_t
			hash_obj.update(path_len.to_bytes(2, byteorder='little'))
		
		hash_obj.update(payload_data)
		
		# Return first 16 hex characters (8 bytes) in uppercase
		return hash_obj.hexdigest()[:16].upper()
	except Exception as e:
		print(f"Error calculating hash: {e}")
		return "0000000000000000"
