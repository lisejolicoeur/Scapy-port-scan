#! /usr/bin/python

from scapy.all import *
import time
 
dst_ip = "172.18.64.17" #input("Targeted IP : ")
src_port = RandShort()

conf.verb=0
ports=range(1,100)
closed=0


def is_up(dst_ip):
    #Tests if host is up
    icmp = IP(dst=dst_ip)/ICMP()
    resp = sr1(icmp, timeout=10)
    if resp == None:
        return False
    else:
        return True

def scanPorts():
	global closed
	if is_up(dst_ip) :
		print("Host ", dst_ip, " is up, start scanning...")
		for port in ports :
			tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=port,flags="S"),timeout=10)
			if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
				print (port, " : Port Closed")
				closed+=1
			elif(tcp_connect_scan_resp.haslayer(TCP)):
				if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
					send_rst = IP(dst=dst_ip)/TCP(sport=src_port,dport=port,flags="AR")
					send(send_rst)
					print (port, " : Port Open")
				elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
					print (port, " : Port Closed")
					closed+=1
		print("Stats : ", closed-1, " ports closed on ",100)
	else:
		print("Host is down.")


scanPorts()

time.sleep(20)
