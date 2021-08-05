
from nintendo.nex import settings, kerberos, common, prudp, rmc, \
	authentication, secure, utility, notification, messaging, \
	ranking2_eagle as ranking2, matchmaking_eagle as matchmaking
from anynet import tls
import itertools
import secrets
import hashlib
import random
import base64
import anyio
import time
import hmac
import json
import math

import dashboard
import config
import eagle

import logging
logging.basicConfig(level=logging.INFO)


SERVER_PID = 257049437023956657
SERVER_KEY = secrets.token_bytes(16)


def check_value(value, check):
	if not check: return True
	
	if "," in check:
		start, end = check.split(",")
		return int(start) <= value <= int(end)
	
	values = [int(v) for v in check.split("|")]
	return value in values

def check_search_criteria(session, crit):
	for i in range(6):
		if not check_value(session.attribs[i], crit.attribs[i]):
			return False
	if not check_value(session.game_mode, crit.game_mode): return False
	if not check_value(session.min_participants, crit.min_participants): return False
	if not check_value(session.max_participants, crit.max_participants): return False
	if not check_value(session.matchmake_system, crit.matchmake_system): return False
	if crit.vacant_only:
		if session.max_participants - session.num_participants < crit.vacant_participants:
			return False
	if crit.exclude_locked and not session.open_participation: return False
	if crit.exclude_user_password and session.user_password_enabled: return False
	if crit.exclude_system_password and session.system_password_enabled: return False
	if crit.codeword and session.codeword != crit.codeword: return False
	return True


class MatchmakeParticipant:
	def __init__(self, pid, message, participants):
		self.pid = pid
		self.message = message
		self.participants = participants


class MatchmakeSession:
	def __init__(self, session):
		self.session = session
		self.participants = {}
		
	def check(self, crit):
		return check_search_criteria(self.session, crit)
		
	def join(self, pid, message, participants):	
		if pid in self.participants:
			raise common.RMCError("RendezVous::AlreadyParticipatedGathering")
		if not self.session.open_participation:
			raise common.RMCError("RendezVous::SessionClosed")
		if self.session.max_participants - self.session.num_participants < participants:
			raise common.RMCError("RendezVous::SessionFull")
		
		self.session.num_participants += participants
		
		participant = MatchmakeParticipant(pid, message, participants)
		self.participants[pid] = participant
	
	def leave(self, pid):
		if pid not in self.participants:
			raise common.RMCError("RendezVous::PermissionDenied")
		
		participant = self.participants.pop(pid)
		self.session.num_participants -= participant.participants
	

class ClientMgr:
	def __init__(self):
		self.clients = {}
	
	def register(self, client):
		self.clients[client.pid()] = client
	
	def disconnect(self, client):
		pid = client.pid()
		if pid in self.clients:
			del self.clients[pid]
	
	async def send_message(self, pid, message):
		if pid in self.clients:
			client = messaging.MessageDeliveryClient(self.clients[pid])
			await client.deliver_message(message)
	
	async def send_notification(self, pid, event):
		if pid in self.clients:
			client = notification.NotificationClient(self.clients[pid])
			await client.process_notification_event(event)


class MatchMaker:
	def __init__(self, clients, eagle):
		self.clients = clients
		self.eagle = eagle
		
		self.session_id = itertools.count(1)
		self.sessions = {}
	
	def get(self, gid):
		if gid not in self.sessions:
			raise common.RMCError("RendezVous::SessionVoid")
		return self.sessions[gid]
	
	def get_joined(self, gid, pid):
		session = self.get(gid)
		if pid not in session.participants:
			raise common.RMCError("RendezVous::PermissionDenied")
		return session
	
	async def send_notification(self, session, event):
		for pid in session.participants:
			await self.clients.send_notification(pid, event)
	
	async def create(self, session, pid):
		session.id = next(self.session_id)
		session.host = pid
		session.owner = pid
		session.started_time = common.DateTime.now()
		
		self.sessions[session.id] = MatchmakeSession(session)
		
		await self.eagle.start(session.id)
	
	async def destroy(self, session, pid):
		event = notification.NotificationEvent()
		event.pid = pid
		event.type = 109000
		event.param1 = session.session.id
		await self.send_notification(session, event)
		
		del self.sessions[session.session.id]
		await self.eagle.stop(session.session.id)
	
	async def join(self, gid, pid, message, participants):
		session = self.get(gid)
		session.join(pid, message, participants)
		
		event = notification.NotificationEvent()
		event.pid = pid
		event.type = 3001
		event.param1 = gid
		event.param2 = pid
		event.param3 = participants
		event.text = message
		
		await self.clients.send_notification(session.session.owner, event)
		
		payload = {
			"expires_at": "%i" %(time.time() + 10800),
			"server_env": "lp1",
			"server_id": "%i" %gid,
			"user_id": "%016x" %pid
		}
		
		signature = hmac.digest(
			eagle.SIGNATURE_KEY, json.dumps(payload).encode(),
			hashlib.sha256
		)
		
		token = json.dumps({
			"payload": payload,
			"signature": base64.b64encode(signature).decode(),
			"version": 1
		})
		
		event = notification.NotificationEvent()
		event.pid = SERVER_PID
		event.type = 200000
		event.param1 = gid
		event.map = {
			"url": "wss://smb35.ymar.dev:20001/%i" %gid,
			"token": base64.b64encode(token.encode()).decode()
		}
		
		await self.clients.send_notification(pid, event)
	
	async def leave(self, gid, pid, message="", disconnected=False):
		session = self.get(gid)
		session.leave(pid)
		
		if pid == session.session.owner:
			if session.session.flags & 0x10 and session.participants:
				await self.migrate(session)
			else:
				await self.destroy(session, pid)
		else:
			event = notification.NotificationEvent()
			event.pid = pid
			event.type = 3007 if disconnected else 3008
			event.param1 = session.session.id
			event.param2 = pid
			event.text = message
			
			await self.clients.send_notification(session.session.owner, event)
	
	async def migrate(self, session):
		new_owner = random.choice(list(session.participants))
		
		event = notification.NotificationEvent()
		event.type = 4000
		event.pid = session.session.owner
		event.param1 = session.session.id
		event.param2 = new_owner
		
		session.session.owner = new_owner
		
		await self.send_notification(session, event)
	
	async def disconnect(self, pid):
		for session in list(self.sessions.values()):
			if pid in session.participants:
				await self.leave(session.session.id, pid)
	
	def browse(self, search_criteria):
		sessions = []
		for session in self.sessions.values():
			if session.check(search_criteria):
				sessions.append(session.session)
		
		offset = search_criteria.range.offset
		if offset == 0xFFFFFFFF:
			offset = 0
		
		size = search_criteria.range.size
		return sessions[offset:offset+size]


class AuthenticationServer(authentication.AuthenticationServerNX):
	def __init__(self, settings):
		super().__init__()
		self.settings = settings
		self.pid = itertools.count(1)
	
	async def validate_and_request_ticket_with_param(self, client, param):
		pid = next(self.pid)
		
		key = secrets.token_bytes(16)
		
		result = authentication.ValidateAndRequestTicketResult()
		result.pid = pid
		result.ticket = self.generate_ticket(pid, SERVER_PID, key, SERVER_KEY)
		result.server_url = common.StationURL(
			scheme="prudps", address="0.0.0.1", port=1,
			PID = SERVER_PID, CID = 1, type = 2,
			sid = 2, stream = 10
		)
		result.server_time = common.DateTime.now()
		result.server_name = "Super Mario Bros. 35"
		result.source_key = key.hex()
		return result
		
	def generate_ticket(self, user_pid, server_pid, user_key, server_key):
		session_key = secrets.token_bytes(32)
		
		internal = kerberos.ServerTicket()
		internal.timestamp = common.DateTime.now()
		internal.source = user_pid
		internal.session_key = session_key
		
		ticket = kerberos.ClientTicket()
		ticket.session_key = session_key
		ticket.target = server_pid
		ticket.internal = internal.encrypt(server_key, self.settings)
		return ticket.encrypt(user_key, self.settings)


class SecureConnectionServer(secure.SecureConnectionServer):
	def __init__(self, clients):
		super().__init__()
		self.clients = clients
		
		self.connection_id = itertools.count(1)
	
	async def logout(self, client):
		self.clients.disconnect(client)
	
	async def register(self, client, urls):
		address, port = client.remote_address()
		
		response = rmc.RMCResponse()
		response.result = common.Result.success()
		response.connection_id = next(self.connection_id)
		response.public_station = common.StationURL(
			scheme="prudp", address=address, port=port,
			natf = 0, natm = 0, pmp = 0, upnp = 0, Tpt = 2,
			type = 11, sid = client.remote_sid()
		)
		
		self.clients.register(client)
		return response


class MatchmakeExtensionServer(matchmaking.MatchmakeExtensionServer):
	def __init__(self, matchmaker):
		super().__init__()
		self.matchmaker = matchmaker
	
	async def logout(self, client):
		await self.matchmaker.disconnect(client.pid())
	
	async def close_participation(self, client, gid):
		session = self.matchmaker.get_joined(gid, client.pid())
		session.session.open_participation = False
	
	async def auto_matchmake_with_param_postpone(self, client, param):
		if param.session.max_participants < param.num_participants:
			raise common.RMCError("Core::InvalidArgument")
		
		sessions = []
		for crit in param.search_criteria:
			sessions += self.matchmaker.browse(crit)
		
		if sessions:
			session = random.choice(sessions)
		else:
			await self.matchmaker.create(param.session, client.pid())
			session = param.session
		
		await self.matchmaker.join(session.id, client.pid(), param.join_message, param.num_participants)
		return session


class MatchMakingServerExt(matchmaking.MatchMakingServerExt):
	def __init__(self, matchmaker):
		super().__init__()
		self.matchmaker = matchmaker
	
	async def end_participation(self, client, gid, message):
		await self.matchmaker.leave(gid, client.pid(), message)
		return True


class MatchMakingServer(matchmaking.MatchMakingServer):
	def __init__(self, matchmaker):
		super().__init__()
		self.matchmaker = matchmaker
	
	async def get_detailed_participants(self, client, gid):
		session = self.matchmaker.get_joined(gid, client.pid())
		
		participants = []
		for participant in session.participants.values():
			details = matchmaking.ParticipantDetails()
			details.pid = participant.pid
			details.name = str(participant.pid)
			details.message = participant.message
			details.participants = participant.participants
			participants.append(details)
		return participants


class MatchmakeRefereeServer(matchmaking.MatchmakeRefereeServer):
	def __init__(self, clients, matchmaker):
		super().__init__()
		self.clients = clients
		self.matchmaker = matchmaker
		
		self.round_id = itertools.count(1)
		self.rounds = {}
	
	async def start_round(self, client, param):
		if not param.pids: raise common.RMCError("Core::InvalidArgument")
		
		gathering = self.matchmaker.get(param.gid)
		if not gathering:
			raise common.RMCError("MatchmakeReferee::NotParticipatedGathering")
		
		for pid in param.pids:
			if pid not in gathering.participants:
				raise common.RMCError("MatchmakeReferee::NotParticipatedGathering")
		
		round_id = next(self.round_id)
		self.rounds[round_id] = param
		
		event = notification.NotificationEvent()
		event.pid = client.pid()
		event.type = 116000
		event.param1 = round_id
		for pid in param.pids:
			await self.clients.send_notification(pid, event)
		
		return round_id
	
	async def get_start_round_param(self, client, round_id):
		if round_id not in self.rounds:
			raise common.RMCError("MatchmakeReferee::RoundNotFound")
		return self.rounds[round_id]
		
	async def end_round(self, client, param):
		if param.round_id not in self.rounds:
			raise common.RMCError("MatchmakeReferee::RoundNotFound")
		
	async def end_round_with_partial_report(self, client, param):
		if param.round_id not in self.rounds:
			raise common.RMCError("MatchmakeReferee::RoundNotFound")


class MessageDeliveryServer(messaging.MessageDeliveryServer):
	def __init__(self, clients, matchmaker):
		super().__init__()
		self.clients = clients
		self.matchmaker = matchmaker
	
	async def deliver_message(self, client, message):
		message.sender = client.pid()
		message.sender_name = str(client.pid())
		message.reception_time = common.DateTime.now()
		if message.recipient.type == messaging.RecipientType.PRINCIPAL:
			await self.clients.send_message(message.recipient.pid)
		elif message.recipient.type == messaging.RecipientType.GATHERING:
			session = self.matchmaker.get_joined(message.recipient.gid, client.pid())
			for participant in session.participants:
				await self.clients.send_message(participant, message)
			
class UtilityServer(utility.UtilityServer):
	def __init__(self):
		super().__init__()
		self.unique_id = itertools.count(1)
		self.associated_ids = {}
	
	async def acquire_nex_unique_id_with_password(self, client):
		info = utility.UniqueIdInfo()
		info.unique_id = next(self.unique_id)
		info.password = secrets.randbits(64)
		return info
	
	async def associate_nex_unique_id_with_my_principal_id(self, client, info):
		self.associated_ids[client.pid()] = info
	
	async def get_associated_nex_unique_id_with_my_principal_id(self, client):
		pid = client.pid()
		if pid in self.associated_ids:
			return self.associated_ids[pid]
		return utility.UniqueIdInfo()
		
	async def get_integer_settings(self, client, index):
		if index == 0: return config.INTEGER_SETTINGS1
		if index == 10: return config.INTEGER_SETTINGS2
		raise common.RMCError("Core::InvalidArgument")


class Ranking2Server(ranking2.Ranking2Server):
	def __init__(self):
		super().__init__()
		self.common_data = {}
	
	async def get_common_data(self, client, flags, pid, unique_id):
		data = self.common_data.get(pid, {})
		if unique_id not in data:
			raise common.RMCError("Ranking2::InvalidArgument")
		return data[unique_id]
	
	async def put_common_data(self, client, data, unique_id):
		pid = client.pid()
		if pid not in self.common_data:
			self.common_data[pid] = {}
		self.common_data[pid][unique_id] = data
	
	async def get_ranking(self, client, param):
		info = ranking2.Ranking2Info()
		info.data = []
		info.lowest_rank = 10000
		info.num_entries = 0
		info.season = 0
		return info
	
	async def get_category_setting(self, client, category):
		setting = ranking2.Ranking2CategorySetting()
		setting.min_score = 0
		setting.max_score = 999999999
		setting.lowest_rank = 10000
		setting.reset_month = 4095
		setting.reset_day = 0
		setting.reset_hour = 0
		setting.reset_mode = 2
		setting.max_seasons_to_go_back = 3
		setting.score_order = 1
		return setting
		
	async def get_estimate_my_score_rank(self, client, input):
		output = ranking2.Ranking2EstimateScoreRankOutput()
		output.rank = 0
		output.length = 0
		output.score = 0
		output.category = input.category
		output.season = 0
		output.sampling_rate = 0
		return output


async def main():
	s = settings.load("switch")
	s.configure("0a69c592", 40600, 0)
	
	chain = tls.load_certificate_chain("resources/fullchain.pem")
	key = tls.TLSPrivateKey.load("resources/privkey.pem", tls.TYPE_PEM)
	context = tls.TLSContext()
	context.set_certificate_chain(chain, key)
	
	async with eagle.serve("", 20001, context) as eagle_mgr:
		clients = ClientMgr()
		matchmaker = MatchMaker(clients, eagle_mgr)
		async with dashboard.serve("", 20002, context, clients, matchmaker):
			servers1 = [AuthenticationServer(s)]
			servers2 = [
				SecureConnectionServer(clients),
				MessageDeliveryServer(clients, matchmaker),
				MatchmakeRefereeServer(clients, matchmaker),
				MatchmakeExtensionServer(matchmaker),
				MatchMakingServerExt(matchmaker),
				MatchMakingServer(matchmaker),
				Ranking2Server(),
				UtilityServer()
			]
			
			async with prudp.serve_transport(s, "", 20000, context) as transport:
				async with rmc.serve_prudp(s, servers1, transport, 1):
					async with rmc.serve_prudp(s, servers2, transport, 2, key=SERVER_KEY):
						print("Server is running!")
						await anyio.sleep(math.inf)
anyio.run(main)
