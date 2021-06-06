
from anynet import util, http, websocket, streams
import contextlib
import secrets
import hashlib
import base64
import anyio
import time
import hmac
import json

import logging
logger = logging.getLogger(__name__)


SIGNATURE_KEY = secrets.token_bytes(32)

N = 11
M = 1024

EAGLE_VERSION = 3
APP_VERSION = 0
DDL_HASH = 0
VERSION_STRING = "2.0.4"


class PacketType:
	ACCEPTED = 0
	LOGIN_REQUEST = 1
	LOGIN_RESULT = 2
	CLIENT_READY = 3
	PING = 4
	PONG = 5
	NODE_NOTICE = 8
	DISCONNECTED = 9
	
	RPC = 16
	
	
class State:
	LOGIN_PHASE0 = 0
	LOGIN_PHASE1 = 1
	WAIT_READY = 2
	READY = 3
	DISCONNECTED = 4


def parse_token(token, server_id):
	token = json.loads(base64.b64decode(token).decode())
	if token["version"] != 1:
		raise ValueError("Token version is invalid")
	
	payload = token["payload"]
	signature = hmac.digest(
		SIGNATURE_KEY, json.dumps(payload).encode(),
		hashlib.sha256
	)
	
	if token["signature"] != base64.b64encode(signature).decode():
		raise ValueError("Token signature is invalid")
	
	if time.time() > int(payload["expires_at"]):
		raise ValueError("Token is expired")
	if payload["server_env"] != "lp1":
		raise ValueError("Token is for wrong environment")
	if payload["server_id"] != str(server_id):
		raise ValueError("Token is for different eagle server")
	return payload["user_id"]


class EagleClient:
	def __init__(self, server, client, node_id):
		self.server = server
		self.client = client
		self.node_id = node_id
		
		self.state = State.LOGIN_PHASE0
		self.token = ""
	
	async def process(self):
		await self.send_accepted()
		
		while self.state != State.DISCONNECTED:
			data = await self.client.recv()
			await self.process_packet(data)
	
	async def process_packet(self, data):
		stream = streams.BitStreamIn(data, ">")
		
		relay_type = stream.bits(2)
		payload_id = stream.bits(8)
		source_id = stream.bits(N)
		
		if relay_type > 2:
			raise ValueError("Invalid relay type: %i" %relay_type)
		
		relay = []
		if relay_type == 1:
			relay.append(stream.bits(N))
		elif relay_type == 2:
			for i in range(M):
				if stream.bit():
					relay.append(i)
		
		stream.bytealign()
		
		logger.debug(
			"Received packet: source=%i type=%i size=%i",
			source_id, payload_id, stream.available()
		)
		
		if payload_id == PacketType.LOGIN_REQUEST:
			await self.process_login_request(stream)
		elif payload_id == PacketType.CLIENT_READY:
			await self.process_client_ready(stream)
		elif payload_id == PacketType.PING:
			await self.process_ping(stream)
		elif payload_id == PacketType.DISCONNECTED:
			await self.process_disconnected(stream)
		elif payload_id >= PacketType.RPC:
			await self.process_rpc(stream, relay, payload_id)
		else:
			raise ValueError("Invalid payload id: %i" %payload_id)
	
	async def process_login_request(self, stream):
		phase = stream.bits(7)
		last_fragment = stream.bit()
		if phase == 0:
			await self.process_login_handshake(stream)
		elif phase == 1:
			await self.process_login_auth(stream, last_fragment)
		else:
			raise ValueError("Invalid login request phase: %i" %phase)
	
	async def process_login_handshake(self, stream):
		if self.state != State.LOGIN_PHASE0:
			raise RuntimeError("Received unexpected login request packet")
		
		connection_check = stream.bits(8)
		eagle_version = stream.bits(32)
		app_version = stream.bits(64)
		ddl_hash = stream.bits(32)
		version = stream.ascii(stream.bits(8))
		
		if connection_check != 0:
			raise ValueError("Login request has unexpected connection check")
		if eagle_version != EAGLE_VERSION:
			raise ValueError("Incorrect eagle version in login request: %i" %eagle_version)
		if app_version != APP_VERSION:
			raise ValueError("Incorrect app version in login request: %i" %app_version)
		if ddl_hash != DDL_HASH:
			raise ValueError("Incorrect DDL has in login request: %i" %ddl_hash)
		
		if version != VERSION_STRING:
			raise ValueError("Incorrect version string in login request: %s" %version)
		
		self.state = State.LOGIN_PHASE1
	
	async def process_login_auth(self, stream, last_fragment):
		if self.state != State.LOGIN_PHASE1:
			raise RuntimeError("Received unexpected login request packet")
		
		self.token += stream.ascii(stream.bits(8))
		if last_fragment:
			user_id = parse_token(self.token, self.server.session_id)
			await self.send_login_result(user_id + "\0")
			
			self.state = State.WAIT_READY
			
	async def process_client_ready(self, stream):
		if self.state != State.WAIT_READY:
			raise RuntimeError("Received unexpected client ready packet")
		
		self.state = State.READY
		await self.server.mark_ready(self)
		
	async def process_ping(self, stream):
		timer = stream.bits(64)
		await self.send_pong(timer)
		
	async def process_disconnected(self, stream):
		self.state = State.DISCONNECTED
	
	async def process_rpc(self, stream, target, rpc_id):
		if self.state != State.READY:
			raise RuntimeError("Received RPC request before client ready")
		
		logger.debug("RPC=%i Targets=%i Size=%i" %(rpc_id, len(target), stream.available()))
		
		time = stream.bits(64)
		payload = stream.readall()
		await self.server.relay_rpc(self, target, rpc_id, payload)
	
	async def send_accepted(self):
		stream = streams.BitStreamOut(">")
		stream.bits(self.node_id, 16)
		stream.bits(int(time.monotonic() * 1000), 64)
		await self.send(PacketType.ACCEPTED, stream.get())
		
	async def send_login_result(self, user_id):
		stream = streams.BitStreamOut(">")
		stream.bits(1, 32)
		stream.bits(0, 8)
		stream.bits(len(user_id), 16)
		stream.ascii(user_id)
		await self.send(PacketType.LOGIN_RESULT, stream.get())
		
	async def send_pong(self, client_time):
		server_time = int(time.monotonic() * 1000)
		
		stream = streams.BitStreamOut(">")
		stream.bits(server_time, 64)
		stream.bits(client_time, 64)
		await self.send(PacketType.PONG, stream.get())
	
	async def send_node_added(self, node_id):
		stream = streams.BitStreamOut(">")
		stream.bits(0, 8)
		stream.bits(node_id, 16)
		stream.bits(int(time.monotonic() * 1000), 64)
		await self.send(PacketType.NODE_NOTICE, stream.get())
	
	async def send_node_removed(self, node_id):
		stream = streams.BitStreamOut(">")
		stream.bits(3, 8)
		stream.bits(node_id, 16)
		stream.bits(int(time.monotonic() * 1000), 64)
		await self.send(PacketType.NODE_NOTICE, stream.get())
		
	async def send_all_nodes(self, node_ids):
		stream = streams.BitStreamOut(">")
		stream.bits(4, 8)
		for i in range(M):
			stream.bit(i in node_ids)
		stream.bits(int(time.monotonic() * 1000), 64)
		await self.send(PacketType.NODE_NOTICE, stream.get())
	
	async def send_rpc(self, source_id, rpc_id, payload):
		stream = streams.BitStreamOut(">")
		stream.bits(int(time.monotonic() * 1000), 64)
		stream.write(payload)
		await self.send(rpc_id, stream.get(), source_id)
	
	async def send(self, type, payload, source=0):
		logger.debug(
			"Sending packet: source=%i type=%i size=%i",
			source, type, len(payload)
		)
		
		stream = streams.BitStreamOut(">")
		stream.bits(0, 2)
		stream.bits(type, 8)
		stream.bits(source, N)
		stream.bytealign()
		stream.write(payload)
		
		try:
			await self.client.send(stream.get())
		except util.StreamError:
			await self.server.remove_node(self)


class EagleServer:
	def __init__(self, router, session_id):
		self.router = router
		self.session_id = session_id
		self.clients = {}
		self.node_id = 0
		
		self.close_request = anyio.create_event()
		
		self.counters = [0] * 32
		
		self.rpcs = {
			17: self.set_server_counter,
			18: self.get_server_counter,
			19: self.increase_server_counter
		}
	
	async def start(self):
		path = "/%i" %self.session_id
		async with websocket.route(self.handle, self.router, path):
			await self.close_request.wait()
	
	async def stop(self):
		await self.close_request.set()
		
	async def handle(self, client):
		self.node_id += 1
		if self.node_id < M:
			client = EagleClient(self, client, self.node_id)
			with util.catch(Exception):
				await client.process()
			await self.remove_node(client)
	
	async def mark_ready(self, client):
		self.clients[client.node_id] = client
		
		await client.send_all_nodes(self.clients)
		
		for other in list(self.clients.values()):
			if other != client:
				await other.send_node_added(client.node_id)
	
	async def remove_node(self, client):
		if client.node_id in self.clients:
			del self.clients[client.node_id]
			
			for other in list(self.clients.values()):
				await other.send_node_removed(client.node_id)
	
	async def relay_rpc(self, source, targets, rpc_id, payload):
		if targets == [M]:
			targets = [c.node_id for c in self.clients.values() if c.state == State.READY and c != source]
		elif targets == [M + 1]:
			targets = [c.node_id for c in self.clients.values() if c.state == State.READY]
		
		for target in targets:
			if target == 0:
				await self.process_rpc(source, rpc_id, payload)
			elif target in self.clients:
				await self.clients[target].send_rpc(source.node_id, rpc_id, payload)
	
	async def process_rpc(self, client, rpc_id, payload):
		logger.info("Received RPC: %i", rpc_id)
		if rpc_id in self.rpcs:
			stream = streams.BitStreamIn(payload, ">")
			await self.rpcs[rpc_id](client, stream)
		else:
			logger.warning("Unknown RPC: %i", rpc_id)
			
	async def get_server_counter(self, client, stream):
		index = stream.bits(8)
		if index < 32:
			await self.send_counter(client, index)
			
	async def set_server_counter(self, client, stream):
		index = stream.bits(8)
		value = stream.bits(64)
		if index < 32:
			self.counters[index] = value
			await self.send_counter(client, index)
	
	async def increase_server_counter(self, client, stream):
		index = stream.bits(8)
		value = stream.bits(64)
		if index < 32:
			self.counters[index] = (self.counters[index] + value) & 0xFFFFFFFFFFFFFFFF
			await self.send_counter(client, index)
	
	async def send_counter(self, client, index):
		stream = streams.BitStreamOut(">")
		stream.bits(index, 8)
		stream.bits(self.counters[index], 64)
		stream.bits(0, 16) # Unknown
		await client.send_rpc(0, 16, stream.get())


class EagleMgr:
	def __init__(self, router, group):
		self.router = router
		self.group = group
		
		self.servers = {}
		
	async def start(self, session_id):
		server = EagleServer(self.router, session_id)
		self.servers[session_id] = server
		
		await self.group.spawn(server.start)
		
	async def stop(self, session_id):
		server = self.servers.pop(session_id)
		await server.stop()


@contextlib.asynccontextmanager
async def serve(host, port, context):
	async with http.serve_router(host, port, context) as router:
		async with util.create_task_group() as group:
			yield EagleMgr(router, group)
