#usr/bin/env python
import shodan
#import censys_io
import time
from commands import getoutput
#from multiprocessing import Process

banner = (
"""
\033[0;90m
 _____           ___
/  __ \          | |
| /  \/ __ _ _ __| |_ ___   __ _ _ __ __ _
| |    / _` | '__| __/ _ \ / _` | '__/ _` |
| \__/\ (_| | |  | || (_) | (_| | | | (_| |
 \____/\__,_|_|   \__\___/ \__, |_|  \__,_|
                            __/ |
                           |___/
\033[0;0m
"""
)

print banner

#pair and organize ASNs
ISP_ASNs = (
	("Speedcast 1","AS9229"),
	("Speedcast 2","AS4913"),
	("Network Innovations 1","AS1821"),
	("Network Innovations 2","AS53828"),
	("EMC-PRIVA-MTN 1","AS32806"),
	("EMC-PRIVA-MTN 2","AS31881"),
	("OmniAccess","AS44431"),
	("SES","AS12684"),
	("ITC Global 1","AS14549"),
#	("ITC Global 2","AS5580"),
	("Globecomm 1","AS24753"),
	("Globecomm 2","AS38056"),
	("Globecomm 3","AS11127"),
	("Globecomm 4","AS11300"),
	("IsoTropic Networks","AS36426"),
	("03B Networks","AS60725"),
	("Marlink","AS5377"),
	("Intelsat","AS22351"),
	("Milano Teleport","AS49284"),
	("KVH Industries","AS25687"),
	("Castor Marine","AS46478"),
	("GlobalTT","AS201004"),
	("BusinessCom Networks 1","AS196916"),
	("BusinessCom Networks 2","AS197206"),
	("NSSLGlobal","AS206437"),
	("Global Data Systems","AS11966"),
	("CeTel","AS39151"),
	("Inmarsat","AS31515")
#	("iDirect","AS40071")
	)

ISP_ASNs_TEST = (
	("Milano Teleport","AS49284"),
	("Marlink", "AS5377")
	)

serv_ports = (
	#service, port, rank, weight
	("SMB", 445, 1, 1.0),
	("NetBIOS 139", 139, 1, 1.0),
	("RDP", 3389, 2, 0.9),
	("WinRM HTTP", 5985, 2, 0.9),
	("WinRM HTTPS", 5986, 2, 0.9),
	("pcAnywhere", 5632, 2, 0.9),
	("MSSQL", 1433, 4, 0.7),
	("MSSQL NI", 1434, 4, 0.7),
	("Oracle DB", 1521, 4, 0.7),
	("Oracle WI", 3339, 4, 0.7),
	("MySQL", 3306, 4, 0.7),
	("NFS share", 2049, 5, 0.6),
	("RPCBind", 111, 5, 0.6),
	("MSRPC", 135, 5, 0.6),
	("NetBIOS 137", 137, 6, 0.5),
	("SSH", 22, 7, 0.4),
	("telnet 23", 23, 7, 0.4),
	("telnet 6001", 6001, 7, 0.4),
	("SNMP", 161, 3, 0.4),
	("FTP", 21, 8, 0.3),
	("SMTP", 25, 9, 0.2),
	("POP3", 110, 9, 0.2),
	("HTTP 80", 80, 10, 0.5),
	("HTTP 8000", 8000, 10, 0.5),
	("HTTP 8080", 8080, 10, 0.5),
	("HTTPS", 443, 10, 0.1)
	)

ISP_conns = list()
ISP_vuln_scores = list()

class enumerator(object):
	def __init__(self):
		self.vsat_enum.__init__(self)

	#returns the sum of all connections (from values in ISP_conns list) for companies in ISP_ASNs tuple
	def total_connections(self):
		global conn_count
		conn_count = 0
		for i in range(len(ISP_conns)):
			conn_count = float(sum(n[1] for n in ISP_conns))
		return conn_count
	#counts number of connections for each company and adds name, ASN, and value to list 'ISP_conns'
	def spec_connections(self, ISP, ASN):
		numCon = int(getoutput("shodan count ASN:" + ASN))
		ISP_conns.append((ISP, numCon, ASN))

	#searches shodan and censys for connections with specific exposures
	def exploitable_ports(self, ISP, ASN, conns):
		#count number of exposures
			count_total = 0
			vuln_total = 0
			timestamp = time.strftime("%c")
			file = open('exposures.txt', 'a+')
			file.write(ISP + " " + timestamp + "\n")
			for service,port,rank,weight in serv_ports:
				count = getoutput("shodan count ASN:" + ASN + " port:{}".format(port))
				count_total += int(count)
				vuln_total += (int(count) * weight)
				if int(count) > 0:
					file.write(service + " - "+ str(count) + "\n")

				if 'SMB' in service:
					if int(count)>0:
						print "exploitable SMB? \033[1;91m YES \033[0m"
					else:
						print "exploitable SMB? \033[1;94m NO \033[0m"
				time.sleep(0.5)

			print "# of exposures: \033[93m" + str(count_total) + "\033[0m"
			vuln_score = round((vuln_total / count_total)*10, 2)
			ISP_vuln_scores.append((ISP, vuln_score))
			print "vulnerability score: " + "\033[93m" + str(vuln_score) + "\033[0m"
			print "\033[0;90m________________________________________\033[0m \n"
	def vsat_enum(self):
		pass


for ISP,ASN in ISP_ASNs:
	enumerator().spec_connections(ISP, ASN)
	time.sleep(0.3)
enumerator().total_connections()
conn_count_int = int(conn_count)
print "Total maritime industry connections(TMIC):\033[94m " + str(conn_count_int) + "\033[0m\n"
print "\033[0;90m________________________________________\033[0m \n"

for ISP,conns,ASN in ISP_conns:
	print "Satellite ISP: " + "\033[92m"+ISP+"\033[0m"
	print "# connections: " + "\033[93m" + str(conns) + "\033[0m"
	print "% of TMIC: " + "\033[93m" + str("{0:.0%}".format(conns/conn_count))+"\033[0m"
	enumerator().exploitable_ports(ISP, ASN, conns)
print ISP_vuln_scores
