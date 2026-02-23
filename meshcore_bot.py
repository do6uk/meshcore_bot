#!/usr/bin/env python3

"""
(c) 2026 Rainer Fiedler - do6uk
https://github.com/do6uk/meshcore_bot

"""

import asyncio, sys, time, urllib.request, urllib.parse, json, io, os
import argparse, configparser, logging

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
#from meshcore import MeshCore, EventType

import packet_hash	# from local directory

## GLOBAL CONSTS

APP = "MeshCore Ping-Bot"
VERSION = "1.4"

ROUTE_TYPENAMES = ["TC_FLOOD", "FLOOD", "DIRECT", "TC_DIRECT"]
PAYLOAD_TYPENAMES = ["REQ", "RESPONSE", "TEXT_MSG", "ACK", "ADVERT", "GRP_TXT", "GRP_DATA", "ANON_REQ", "PATH", "TRACE", "MULTIPART", "CONTROL"]
CONTACT_TYPENAMES = ["NONE","CLI","REP","ROOM","SENS"]

## GLOBAL VARS

meshcore_app_name = 'ping-bot'

ping_chan_blocktimes = {}
ping_priv_blocktimes = {}
waiting_ack = {}
running = True

class config:
	log_level = logging.INFO
	
	connection = False
	port = False
	
	ping_chan_active = True
	ping_channels = ['#ping']
	ping_channel_scopes = {'#ping':'local-scope'}
	ping_chan_keyword = 'ping'
	ping_chan_blocktime = 5
	ping_chan_block_whitelist = []
	ping_chan_maxhop = 5
	ping_chan_message = 'PONG {contact} {time} {time_diff} {snr} {hops} {path} {max_hops} {blocktime}'
	
	ping_priv_active = False
	ping_priv_keyword = '/ping'
	ping_priv_blocktime = 5
	ping_priv_message = 'PONG {time} {time_diff} {snr} {hops} {path} {blocktime}'
	
	tg_active = False
	tg_url = 'https://server.tld/your-telegram-bot.php'
	tg_sender = 'MeshCore: '
	tg_apikey_chan = '*ChannelKey*'
	tg_apikey_priv = '*PrivateKey*'
	
	tg_relay_channels = []
	tg_relay_priv = False
	tg_relay_ping = False
	
	parser = configparser.ConfigParser()
	
	filename = 'meshcore_bot.conf'
	
	def __init__(self):
		self.parser.add_section('device')
		self.parser.add_section('ping.channel')
		self.parser.add_section('ping.private')
		self.parser.add_section('telegrambot')
		self.parser.add_section('telegrambot.relay')
		
		self.parser.set('DEFAULT','log_level', logging.getLevelName(self.log_level))
		
		self.parser.set('device','connection', str(self.connection))
		self.parser.set('device','port', str(self.port))
		
		self.parser.set('ping.channel', 'active', str(self.ping_chan_active))
		self.parser.set('ping.channel', 'channels', json.dumps(self.ping_channels))
		self.parser.set('ping.channel', 'channel_scope', json.dumps(self.ping_channel_scopes))
		self.parser.set('ping.channel', 'keyword', self.ping_chan_keyword)
		self.parser.set('ping.channel', 'blocktime', str(self.ping_chan_blocktime))
		self.parser.set('ping.channel', 'blocktime_whitelist', json.dumps(self.ping_chan_block_whitelist))
		self.parser.set('ping.channel', 'maxhop', str(self.ping_chan_maxhop))
		self.parser.set('ping.channel', 'message', self.ping_chan_message)
		
		self.parser.set('ping.private', 'active', str(self.ping_priv_active))
		self.parser.set('ping.private', 'keyword', self.ping_priv_keyword)
		self.parser.set('ping.private', 'blocktime', str(self.ping_priv_blocktime))
		self.parser.set('ping.private', 'message', self.ping_priv_message)
		
		self.parser.set('telegrambot', 'active', str(self.tg_active))
		self.parser.set('telegrambot', 'bot_url', self.tg_url)
		self.parser.set('telegrambot', 'sender', self.tg_sender)
		self.parser.set('telegrambot', 'apikey_channel', self.tg_apikey_chan)
		self.parser.set('telegrambot', 'apikey_private', self.tg_apikey_priv)
		
		self.parser.set('telegrambot.relay', 'channels', json.dumps(self.tg_relay_channels))
		self.parser.set('telegrambot.relay', 'private', str(self.tg_relay_priv))
		self.parser.set('telegrambot.relay', 'ping', str(self.tg_relay_ping))
	
	def write(self):
		conf_file = open(self.filename,'w')
		self.parser.write(conf_file)
		
	def read(self):
		self.parser.read(self.filename)
		
		temp_log_level = self.parser.get('DEFAULT','log_level', fallback = self.log_level)
		log_levels = logging.getLevelNamesMapping()
		if temp_log_level in log_levels:
			self.log_level = log_levels[temp_log_level]
		
		self.connection = self.parser.get('device','connection', fallback = self.connection).lower()
		self.port = self.parser.get('device','port', fallback = self.port)
		
		self.ping_chan_active = self.parser.getboolean('ping.channel', 'active', fallback = self.ping_chan_active)
		self.ping_channels = json.loads(self.parser.get('ping.channel', 'channels', fallback = json.dumps(self.ping_channels)))
		self.ping_channel_scopes = json.loads(self.parser.get('ping.channel', 'channel_scopes', fallback = json.dumps(self.ping_channel_scopes)))
		self.ping_chan_keyword = self.parser.get('ping.channel', 'keyword', fallback = self.ping_chan_keyword)
		self.ping_chan_blocktime = self.parser.getint('ping.channel', 'blocktime', fallback = self.ping_chan_blocktime)
		self.ping_chan_block_whitelist = json.loads(self.parser.get('ping.channel', 'blocktime_whitelist', fallback = json.dumps(self.ping_chan_block_whitelist)))
		self.ping_chan_maxhop = self.parser.getint('ping.channel', 'maxhop', fallback = self.ping_chan_maxhop)
		self.ping_chan_message = self.parser.get('ping.channel', 'message', fallback = self.ping_chan_message)
		if self.ping_chan_message.startswith(("'",'"')) and self.ping_chan_message.endswith(("'",'"')):
			self.ping_chan_message = self.ping_chan_message[1:-1]
		
		self.ping_priv_active = self.parser.getboolean('ping.private', 'active', fallback = self.ping_priv_active)
		self.ping_priv_keyword = self.parser.get('ping.private', 'keyword', fallback = self.ping_priv_keyword)
		self.ping_priv_blocktime = self.parser.getint('ping.private', 'blocktime', fallback = self.ping_priv_blocktime)
		self.ping_priv_message = self.parser.get('ping.private', 'message', fallback = self.ping_priv_message)
		if self.ping_priv_message.startswith(("'",'"')) and self.ping_priv_message.endswith(("'",'"')):
			self.ping_priv_message = self.ping_priv_message[1:-1]
		
		self.tg_active = self.parser.getboolean('telegrambot', 'active', fallback = self.tg_active)
		self.tg_url = self.parser.get('telegrambot', 'bot_url', fallback = self.tg_url)
		self.tg_sender = self.parser.get('telegrambot', 'sender', fallback = self.tg_sender)
		self.tg_apikey_chan = self.parser.get('telegrambot', 'apikey_channel', fallback = self.tg_apikey_chan)
		self.tg_apikey_priv = self.parser.get('telegrambot', 'apikey_private', fallback = self.tg_apikey_priv)
		
		self.tg_relay_channels = json.loads(self.parser.get('telegrambot.relay', 'channels', fallback = json.dumps(self.tg_relay_channels)))
		self.tg_relay_priv = self.parser.getboolean('telegrambot.relay', 'private', fallback = self.tg_relay_priv)
		self.tg_relay_ping = self.parser.getboolean('telegrambot.relay', 'ping', fallback = self.tg_relay_ping)
		
		if not os.path.exists(self.filename):
			bot_logger.error(f'[conf] file {self.filename} not found - will create with defaults ...')
			self.write()


def tg_send(msg):
	if conf.tg_active:
		sender = conf.tg_sender + msg['sender']
		
		if msg['type'] == 'chan':
			title = 'Message in '+msg['channel']
			apikey = conf.tg_apikey_chan
			bot_logger.info(f"[tg_relay] channel-message {msg['text']}")
		else:
			title = 'Message from '+msg['from']
			apikey = conf.tg_apikey_priv
			bot_logger.info(f"[tg_relay] private-message {msg['text']}")
		
		message = msg['text']
		try:
			response = urllib.request.urlopen(conf.tg_url+'?apikey='+urllib.parse.quote_plus(apikey)+'&message='+urllib.parse.quote_plus(message)+'&title='+urllib.parse.quote_plus(title)+'&sender='+urllib.parse.quote_plus(sender))
			if response.status != 200:
				bot_logger.error(f"[tg_relay] failed with {response.status} @ {response.url}")
		except:
			bot_logger.error(f"[tg_relay] failed with before request @ {response.url}")

	else:
		bot_logger.debug(f"[tg_relay] inactive")

def readable_path(path):
	path_list = []
	for i in range(0, len(path), 2):
		path_list.append(path[i:i+2])
	
	return ','.join(path_list)

def ip_to_tuple(ip):
	try:
		ip, port = ip.split(':')
	except:
		port = 5000
	return (ip, int(port))

def check_ack(ack_code):
	if ack_code in waiting_ack:
		secs = int(time.time()-waiting_ack[ack_code])
		bot_logger.debug(f"waiting ack {ack_code} for {secs}s")
		
		if secs < waiting_ack_secs:
			bot_logger.debug(f"removed ack in time {ack_code}")
			del waiting_ack[ack_code]
			return True
		else:
			bot_logger.debug(f"removed ack out of time {ack_code}")
			del waiting_ack[ack_code]
			return False
	
	else:
		for ack in waiting_ack.copy():
			if time.time() - waiting_ack[ack] > waiting_ack_secs:
				bot_logger.debug(f"cleaning outdated ack {ack}")
				del waiting_ack[ack]
		
		bot_logger.debug(f"added new ack {ack_code}")
		waiting_ack[ack_code] = time.time()
		return True

async def main():
	global running
	
	channels = {}
	get_channels = []
	rx_log = {}
	rx_log_priv = {}
	
	async def on_connected(event):
		print(time.strftime('%H:%M:%S'),'CONNECTED', f"\n {event.payload}")
		if event.payload.get('reconnected'):
			bot_logger.info(f"re-connected @ {conf.port}")
	
	async def on_disconnected(event):
		global running
		print(time.strftime('%H:%M:%S'), 'DISCONNECTED', f"\n {event.payload['reason']}")
		if event.payload.get('max_attempts_exceeded'):
			bot_logger.error(f"{conf.port} failed - max attemps exceeded")
			sys.exit()
	
	async def on_device_info(event):
		bot_logger.debug(f"DEVICE_INFO: {event}")
	
	async def on_ack(event):
		bot_logger.debug(f"ACK: {event}")
		ack_code = event.payload['code']
		result = check_ack(ack_code)
	
	async def on_self_info(event):
		bot_logger.debug(f"SELF_INFO: {event}")
		device_name = event.payload['name']
		bot_logger.info(f"device name: {device_name}")
	
	async def on_event(event):
		print('on_event',event,'\n')
	
	async def on_message(event):
		result = await meshcore.commands.get_contacts()
				
		bot_logger.debug(f"[ping_bot] MSG_RAW: {event}")
		
		msg = event.payload
		msg_key = msg['pubkey_prefix']
		msg_text = msg['text']
		msg_received = time.strftime('%H:%M:%S')
		
		# try:
			# msg_rx = rx_log_priv[msg_key]
		# except:
			# msg_rx = {'path': '', 'path_len': msg['path_len'], 'timestamp': 0}
		
		contact = meshcore.get_contact_by_key_prefix(msg_key)
		try:
			path = contact['out_path']
			path_len = contact['out_path_len']
			msg_from = contact['adv_name']
		except:
			path = ''
			path_len = 0
			msg_from = msg_key
		
		bot_logger.info(f"[ping_bot] checking in private message : {msg_from}: {msg_text} | last known path {readable_path(path)}")
		
		if conf.tg_relay_priv:
			tg_msg = {'text': msg_text, 'from': msg_from, 'type': 'priv', 'sender': device_name}
			tg_send(tg_msg)
		
		if msg_text.lower().startswith(conf.ping_priv_keyword) or msg_text == '@':
			bot_logger.debug(f"[ping-bot] bot triggered by {msg_from} with private message")
			
			if msg_key in ping_priv_blocktimes:
				last_ping = ping_priv_blocktimes[msg_key]
				if time.time() < last_ping + (conf.ping_priv_blocktime*60):
					bot_logger.info(f"[ping_bot] {msg_from} in blocktime - exit ...")
					return
				else:
					del ping_priv_blocktimes[msg_key]
			
			# if path_len == 0:
				# path_len = 'direct'
				
			try:
				ping_snr = str(msg['SNR'])
			except:
				ping_snr = '?'
				bot_logger.debug(f"[ping-bot] {msg_from} SNR not available")
			
			## time
			ping_sent = msg['sender_timestamp']
			ping_diff = str(int(time.time()-ping_sent))
			
			ping_msg = conf.ping_priv_message
			ping_msg = ping_msg.replace('\\n', '\n')
			ping_msg = ping_msg.replace('{time}', str(msg_received))
			ping_msg = ping_msg.replace('{time_diff}', str(ping_diff))
			ping_msg = ping_msg.replace('{hops}', str(path_len))
			ping_msg = ping_msg.replace('{blocktime}', str(conf.ping_priv_blocktime))
			
			if path != '':
				ping_msg = ping_msg.replace('{path}', f"[{readable_path(path)}]")
			else:
				ping_msg = ping_msg.replace('{snr}', '📶 ' + str(ping_snr))
			
			ping_msg = ping_msg.replace('{path}', 'direct')
			ping_msg = ping_msg.replace('{snr}', '')
			
			ping_priv_blocktimes[msg_key] = time.time()
			bot_logger.debug(f"[ping-bot] {msg_from} set blocktime until {int(ping_priv_blocktimes[msg_key])}")
			
			try:
				bot_logger.info(f"[ping-bot] send reply ...\n {ping_msg}")
				
				result = await meshcore.commands.send_msg_with_retry(msg_key, ping_msg, max_attempts=2, max_flood_attempts=1, flood_after=1)
				if result:
					bot_logger.debug(f"[ping-bot] send reply - result: {result}")
				else:
					bot_logger.error(f"[ping-bot] send reply - FAILED WITH NO RESULT!")
			except:
				bot_logger.debug(f"[ping-bot] error while sending message {ping_msg}")
				pass
			
			if conf.tg_relay_priv:
				try:
					bot_logger.debug(f"[ping-bot] relaying to TG:\n {ping_msg}")
					tg_msg = {'text': ping_msg, 'from': msg_from, 'type': 'priv', 'sender': device_name}
					tg_send(tg_msg)
				except:
					bot_logger.debug(f"[ping-bot] error while relaying message to TG")
					pass
	
	async def on_channel_message_ping(event):
		bot_logger.debug(f"[ping_bot] CHAN_RAW: {event}")
		
		msg = event.payload
		channel_idx = msg['channel_idx']
		channel = channels[channel_idx]
		
		msg_split = msg['text'].split(': ',1)
		msg_contact = msg_split[0]
		msg_text = msg_split[1]
		msg_received = time.strftime('%H:%M:%S')
		
		try:
			msg_rx = rx_log[msg['text']]
		except:
			msg_rx = {'path': '', 'path_len': msg['path_len'], 'timestamp': 0}
		
		bot_logger.info(f"[ping_bot] checking in {channel} (#{msg['channel_idx']}): {msg['text']} ({msg['path_len']} hops)")
		
		if channels[msg['channel_idx']] in conf.tg_relay_channels:
			tg_msg = {'text': msg['text'], 'channel': channel, 'from': msg_contact, 'type': 'chan', 'sender': device_name}
			tg_send(tg_msg)
		
		if msg_text.lower().startswith(conf.ping_chan_keyword):
			bot_logger.debug(f"[ping_bot] triggered in {channel}")
			ping_hops = msg['path_len']
			ping_snr = msg['SNR']
			ping_sent = msg['sender_timestamp']
			ping_diff = int(time.time()-ping_sent)
			
			if ping_hops == 255:
				ping_hops = 0
			
			if ping_hops > conf.ping_chan_maxhop:
				bot_logger.info(f"[ping_bot] {msg_contact} reached max hops {ping_hops}/{conf.ping_chan_maxhop} - exit ...")
				return
			
			if msg_contact in ping_chan_blocktimes:
				block_remain = int(ping_chan_blocktimes[msg_contact] + (conf.ping_chan_blocktime*60) - time.time())
				
				if block_remain > 60:
					block_remain_str = str(int(block_remain/60))+'min '+str(block_remain-(int(block_remain/60)*60))+'sec'
				else:
					block_remain_str = int(block_remain)
				
				if msg_contact in conf.ping_chan_block_whitelist:
					bot_logger.info(f"[ping_bot] {msg_contact} in blocktime {block_remain_str}s & whitelisted - override blocktime ...")
					block_remain = 0
				
				if block_remain > 0:
					bot_logger.info(f"[ping_bot] {msg_contact} in blocktime {block_remain_str} - exit ...")
					return
				else:
					del ping_chan_blocktimes[msg_contact]
			
			try:
				ping_scope = conf.ping_channel_scopes[channel]
			except:
				ping_scope = None
			
			ping_msg = conf.ping_chan_message
			ping_msg = ping_msg.replace('\\n', '\n')
			ping_msg = ping_msg.replace('{contact}', '@[' + msg_contact + ']')
			ping_msg = ping_msg.replace('{time}', str(msg_received))
			ping_msg = ping_msg.replace('{time_diff}', str(ping_diff))
			ping_msg = ping_msg.replace('{max_hops}', str(conf.ping_chan_maxhop))
			ping_msg = ping_msg.replace('{blocktime}', str(conf.ping_chan_blocktime))
			
			if msg_rx['timestamp'] >= (time.time()-10):
				path = msg_rx['path']
				if path != '':
					ping_msg = ping_msg.replace('{path}', f"[{readable_path(path)}]")
				else:
					ping_msg = ping_msg.replace('{snr}', '\n📶 ' + str(ping_snr))
					ping_msg = ping_msg.replace('{hops}', '')
			
			if ping_scope != None:
				ping_msg = ping_msg.replace('{scope}', '\n🇸 '+ping_scope)
				ping_scope_msg = 'with scope '+ping_scope
			else:
				ping_msg = ping_msg.replace('{scope}', '')
				ping_scope_msg = ''
			
			ping_msg = ping_msg.replace('{hops}', str(ping_hops))
			ping_msg = ping_msg.replace('{path}', '')
			ping_msg = ping_msg.replace('{snr}', '')
			
			ping_msg_len = len(ping_msg)
			
			bot_logger.info(f"[ping_bot] responds:\n {ping_msg} {ping_msg_len}/122 {ping_scope_msg}")
			time.sleep(2)
			result_scope = await meshcore.commands.set_flood_scope('#'+ping_scope)
			time.sleep(0.5)
			result_msg = await meshcore.commands.send_chan_msg(channel_idx, ping_msg)
			time.sleep(0.5)
			result_reset_scope = await meshcore.commands.set_flood_scope(None)
			
			ping_chan_blocktimes[msg_contact] = time.time()
			
			if conf.tg_relay_ping:
				tg_msg = {'text': ping_msg, 'channel': channel, 'from': msg_contact, 'type': 'chan', 'sender': device_name}
				tg_send(tg_msg)
	
	async def handle_log_rx(event):
		for m in list(rx_log):
			if rx_log[m]['timestamp'] < time.time()-60:
				bot_logger.debug(f"[rx_log] cleaning ... {rx_log[m]['timestamp']}") 
				del rx_log[m]
		
		mc = handle_log_rx.mc
		
		pkt = bytes().fromhex(event.payload["payload"])
		pbuf = io.BytesIO(pkt)
		header = pbuf.read(1)[0]
		route_type = header & 0x03
		payload_type = (header & 0x3c) >> 2
		payload_ver = (header & 0xc0) >> 6
		
		transport_code = None
		if route_type == 0x00 or route_type == 0x03: # has transport code
			transport_code = pbuf.read(4)    # discard transport code
		
		path_len = pbuf.read(1)[0]
		path = pbuf.read(path_len).hex() # Beware of traces where pathes are mixed
		
		try :
			route_typename = ROUTE_TYPENAMES[route_type]
		except IndexError:
			bot_logger.debug(f"[rx_log] Unknown route type {route_type}") 
			route_typename = "UNK"
		
		try :
			payload_typename = PAYLOAD_TYPENAMES[payload_type]
		except IndexError:
			bot_logger.debug(f"[rx_log] Unknown payload type {payload_type}")
			payload_typename = "UNK"
		
		pkt_payload = pbuf.read()
		
		event.payload["header"] = header
		event.payload["route_type"] = route_type
		event.payload["route_typename"] = route_typename
		event.payload["payload_type"] = payload_type
		event.payload["payload_typename"]= payload_typename
		event.payload["payload_ver"] = payload_ver
		
		if not transport_code is None:
			event.payload["transport_code"] = transport_code.hex()
		
		event.payload["path_len"] = path_len 
		event.payload["path"] = path
		event.payload["pkt_payload"] = pkt_payload.hex()
		
		if payload_type == 0x05: # flood msg / channel
			pk_buf = io.BytesIO(pkt_payload)
			chan_hash = pk_buf.read(1).hex()
			cipher_mac = pk_buf.read(2)
			msg = pk_buf.read() # until the end of buffer
			
			channel = None
			for c in get_channels:
				if c["channel_hash"] == chan_hash : # validate against MAC
					h = HMAC.new(bytes.fromhex(c["channel_secret"]), digestmod=SHA256)
					h.update(msg)
					if h.digest()[0:2] == cipher_mac:
						channel = c
						break
			
			chan_name = ""
			
			if channel is not None:
				chan_name = channel["channel_name"]
				aes_key = bytes.fromhex(channel["channel_secret"])
				cipher = AES.new(aes_key, AES.MODE_ECB)
				message = cipher.decrypt(msg)[5:].decode("utf-8", "ignore").strip("\x00")
				message_from = msg_split = message.split(': ',1)[0]
				
				if chan_name in conf.ping_channels:
					if chan_name != "" :
						rx_log[message] = {'timestamp': time.time(), 'path': path, 'path_len': path_len}
						
						if bot_logger.level == logging.DEBUG:
							txt = f"Ch: {chan_name} Msg: {message} Path [{readable_path(path)}] SNR {event.payload['snr']:6,.2f}"
							bot_logger.debug(f"[rx_log] {txt}")
						else:
							txt = f"Ch: {chan_name} From: {message_from} Path [{readable_path(path)}] SNR {event.payload['snr']:6,.2f}"
							bot_logger.info(f"[rx_log] {txt}")
				else:
					txt = f"Ch: {chan_name} Msg: {message} Path [{readable_path(path)}] SNR {event.payload['snr']:6,.2f}"
					bot_logger.debug(f"[rx_log] {txt}")
	
	# Connect to your device
	if conf.connection == 'serial':
		bot_logger.debug(f"using serial device @ {conf.port}")
		meshcore = await MeshCore.create_serial(conf.port, auto_reconnect=True)
	elif conf.connection == 'tcp':
		host, port = ip_to_tuple(conf.port)
		bot_logger.debug(f"using TCP device @ {host}:{port}")
		try:
			meshcore = await MeshCore.create_tcp(host, port, auto_reconnect=True)
		except:
			bot_logger.error(f"device @ {host}:{port} not reachable ... exit ...")
			sys.exit()
	else:
		bot_logger.error(f"device @ not set by CLI or config ... exit ...")
		sys.exit()
	
	if meshcore.is_connected:
		bot_logger.info('device connected')
	
	meshcore.subscribe(EventType.CONNECTED, on_connected)
	meshcore.subscribe(EventType.DISCONNECTED, on_disconnected)
	
	result = await meshcore.commands.send_appstart()
	try:
		device_name = result.payload['name']
	except Exception as err:
		print('error',err)
		device_name = '???'
	
	try:
		public_key = result.payload['public_key']
	except Exception as err:
		print('error',err)
		public_key = '???'
	
	await meshcore.commands.send_advert(flood=True)
	result = await meshcore.commands.get_contacts()
	
	ch_idx = 0
	while True:
		result = await meshcore.commands.get_channel(ch_idx)
		chan_name = result.payload['channel_name']
		if result.type == EventType.ERROR or chan_name == '':
			break
		channels[result.payload['channel_idx']] = chan_name
		
		info = result.payload
		info["channel_hash"] = SHA256.new(info["channel_secret"]).hexdigest()[0:2]
		info["channel_secret"] = info["channel_secret"].hex()
		get_channels.append(info)
		
		ch_idx = ch_idx+1
		
		if chan_name in conf.ping_channels:
			bot_logger.info(f"[ping_bot] subscribing channel {chan_name}")
			
			meshcore.subscribe(
				EventType.CHANNEL_MSG_RECV,
				on_channel_message_ping,
				attribute_filters={"channel_idx": result.payload['channel_idx']}
			)

	await meshcore.start_auto_message_fetching()

	meshcore.subscribe(EventType.DEVICE_INFO, on_device_info)
	meshcore.subscribe(EventType.SELF_INFO, on_self_info)

	handle_log_rx.mc = meshcore
	meshcore.subscribe(EventType.RX_LOG_DATA, handle_log_rx)
	
	meshcore.subscribe(EventType.PATH_UPDATE, on_event)
	meshcore.subscribe(EventType.PATH_RESPONSE, on_event)
	# meshcore.subscribe(EventType.ACK, on_event)

	if conf.ping_priv_active:
		meshcore.subscribe(EventType.CONTACT_MSG_RECV, on_message)
	
	try:
		# Keep the main program running
		await asyncio.sleep(float('inf'))

	except asyncio.CancelledError:
		# Clean up when program ends
		await meshcore.disconnect()

# prepare logger
LOG_FORMAT = '%(levelname)-5s %(message)s'
#LOG_FORMAT = '%(asctime)-15s %(levelname)-10s %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)
bot_logger = logging.getLogger(__name__)

from meshcore import MeshCore, EventType

# CLI-interface
parser = argparse.ArgumentParser(description='meshcore ping bot')
parser.add_argument('-t', '--tcp', help='Device IP and port, i.e.: 127.0.0.1:5000')
parser.add_argument('-s', '--serial', help='serial port, i.e.: /dev/ttyUSB0')
parser.add_argument('-c', '--config', help='filename of configfile to use')
parser.add_argument('-ver', '--version', action='store_true', help='shows current app-version')
output_group = parser.add_mutually_exclusive_group()
output_group.add_argument('-q', '--quiet', action='store_true', help='minimal logging to CLI')
output_group.add_argument('-v', '--verbose', action='store_true', help='maximum logging to CLI')
args = parser.parse_args()

# init config
conf = config()

# check if config-file is set by CLI
if args.config:
	conf.filename = args.config
	bot_logger.info(f'config-file is set to {conf.filename}')

# read config
conf.read()

# read log_level from CLI - overriding conf-values
if args.quiet:
	conf.log_level = logging.CRITICAL
if args.verbose:
	conf.log_level = logging.DEBUG

# set log_level
bot_logger.setLevel(conf.log_level)
if bot_logger.getEffectiveLevel() == logging.DEBUG:
	bot_logger.info('LOGLEVEL is set to DEBUG')

# read connection from CLI
if args.tcp:
	conf.connection = 'tcp'
	conf.port = args.tcp
	bot_logger.debug('connection set by command line: TCP {args.tcp}')
elif args.serial:
	conf.connection = 'serial'
	conf.port = args.serial
	bot_logger.debug('connection set by command line: SERIAL {args.serial}')

# check if connection is set - exit if not
if not conf.connection or conf.connection == 'false':
	print('\nERROR: you need to use -s or -t or config-file to connect to your device\n')
	parser.print_help()
	sys.exit()


#bot_logger.info(f"Welcome {APP} v{VERSION}")
print(f"{APP} v{VERSION} - Welcome")

if args.version:
	sys.exit()

asyncio.run(main())
