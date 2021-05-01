
from nintendo.nex import common
from anynet import http
import contextlib


TEMPLATE = """
<!doctype html>
<html>
	<head>
		<style>
			body {
				font-family: monospace;
				font-size: 14px;
				
				padding: 20px;
			}
			
			table {
				border-collapse: collapse;
			}
			
			td, th {
				border: 1px solid black;
				
				text-align: right;
				padding: 5px;
			}
		</style>
	</head>
	<body>
		Current server time: %s<br><br>
		
		Server boot time: %s<br><br>
		
		Number of connected clients: %i<br><br>
		
		Active matchmake sessions:<br><br>
		
		<table>
			<tr><th>ID</th><th>Game mode</th><th>Participants</th><th>Start time</th></tr>
%s
		</table>
	</body>
</html>
"""

ROW_TEMPLATE = "\t\t\t<tr><td>%i</td><td>%i</td><td>%i</td><td>%s</td></tr>"


class Dashboard:
	def __init__(self, clients, matchmaker):
		self.clients = clients
		self.matchmaker = matchmaker
		
		self.start_time = common.DateTime.now()
	
	async def handle(self, client, request):
		rows = []
		for session in self.matchmaker.sessions.values():
			info = session.session
			rows.append(ROW_TEMPLATE %(
				info.id, info.game_mode, info.num_participants,
				info.started_time
			))
		
		response = http.HTTPResponse(200)
		response.headers["Content-Type"] = "text/html"
		response.text = TEMPLATE %(
			common.DateTime.now(), self.start_time,
			len(self.clients.clients), "\n".join(rows)
		)
		return response


@contextlib.asynccontextmanager
async def serve(host, port, context, clients, matchmaker):
	dashboard = Dashboard(clients, matchmaker)
	async with http.serve(dashboard.handle, host, port, context):
		yield
