import socket

class TransportTCP():
	
	s = None
	ip = ""
	port = 0
	
	def __init__(self, ip, port):
		self.ip = ip
		self.port = port

	def send(self, data):
		if self.s is not None:
			self.s.send(data)
			response = self.s.recv(1024)
			return response
		return bytes()

	def stop(self):
		if self.s is not None:
			self.s.close()
			self.s = None
		
	def start(self):
		self.stop()
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.settimeout(2)
		self.s.connect((self.ip, self.port))

