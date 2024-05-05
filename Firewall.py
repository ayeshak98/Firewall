from scapy.all import *
class Firewall:
	def __init__(self):
		self.rules = []

	def add_rule(self,rule):
		self.rules.append(rule)

	def packet_filter(self, packet):
		for rule in self.rules:
			if rule.matches(packet)
			if rule.action == "drop":
				print("Packet dropped:", packet.summary())
				return
			elif rule.action == "allow":
				print("Packet allowed:", packet.summary())
				send(packet)
				return
		print("Packet not matched by any rule, dropping:", packet.summary())

class Rule:
	def __init__(self, protocol=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None, action="allow"):
		self.protocol = protocol
		self.src_ip = src_ip
		self.dst_ip = dst_ip
		self.src_port = src_port
		self.dst_port = dst_port
		self.action = action

	def matches(self, packet):
		if self.protocol and packet.haslayer(self.protocol):
			if self.src_ip and packet[IP].serc != self.src_ip:
				return False
			if self.dst_ip and packet[IP].dst != self.dst_ip:
				return False
			if self.src_port and packet[self.protocol].sport != self.src_port:
				return False
			if self.dst_port and packet[self.protocol].dport != self.dst_port:
				return False
			return True
		return False

# Create a firewall instance
firewall = Firewall()

# Add some rules
# Allow outbound HTTP traffic
firewall.add_rule(Rule(protocol=TCP, src_ip="192.168.56.1", dst.port=80, action="allow"))
# Drop inbound traffic from specific IP
firewall.add_rule(Rule(src_ip="192.168.1.100", action="drop"))

# Sniff packets and apply firewall rules
sniff(prn=firewall.packet_filter, store=0)
