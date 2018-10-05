#!/usr/bin/python2.7
#credit to phillips321 for many of the functions for converting the ip addresses and getting started with argparsehttps://www.phillips321.co.uk/2014/08/12/python-port-scanner-nmap-py/


import socket
import subprocess
import sys
import argparse
import re
import colorama
from colorama import Fore,Style
from datetime import datetime

def main():
	title = """
        _______ ______  _____   ______ _______ _______ _______ __   _
 |      |_____|  ____/ |     | |_____/ |______ |       |_____| | \  |
 |_____ |     | /_____ |_____| |    \_ ______| |_____  |     | |  \_|
                                                                     
"""
	#stores all the arguments made at time of running
	parser = argparse.ArgumentParser(description='lazorScan.py - Simple python port scanner')
	parser.add_argument('-sS', '--tcpscan', action='store_true', help='Enable this for TCP scans')
	parser.add_argument('-p', '--ports', default='1-1024', help='The ports you want to scan (21,22,80,135-139,443,445)')
	parser.add_argument('-tr', '--traceroute',action='store_true', help='Set this flag to perform a traceroute')
	parser.add_argument('-t', '--targets', help='The target(s) you want to scan (192.168.0.1)')
	parser.add_argument('-I', '--icmp', action='store_true', help='Set this flag to perform an ICMP scan')
	parser.add_argument('-sV', '--servicescan', action='store_true', help='Set this if you want to attempt to grab service names')
	parser.add_argument('-f', '--fileread', help='Use this to have the program read a list of targets from a text file')

	if len(sys.argv)==1: parser.print_help(); sys.exit(0)
	
	args = parser.parse_args()
	
	# Set target (and convert for FQDN)
	targets=[]
	if args.targets:
		if '/' in args.targets: #found cidr target
			targets = returnCIDR(args.targets)
		elif '-' in args.targets:
			targets = iprange(args.targets)
		elif ',' in args.targets:
			targets = args.targets.split(",")#handles lists of ip addresses
		else:
			try: targets.append(socket.gethostbyname(args.targets)) # get IP from FQDN
			except: errormsg("Failed to translate hostname to IP address")
	elif args.fileread:
		try:
			f = open(args.fileread,"r")
		except:
			print "File does not exist"
			return
		for x in f:
			targets.append(x)
	else: parser.print_help(); errormsg("You need to set a hostname")#no ip given
	# Set ports
	if args.ports == '-': args.ports = '1-65535'
	ranges = (x.split("-") for x in args.ports.split(","))
	ports = [i for r in ranges for i in range(int(r[0]), int(r[-1]) + 1)]
	# Start Scanning
	t1 = datetime.now()
	print(Fore.GREEN + title + Style.RESET_ALL)
	for target in targets:
		if args.traceroute:
			traceroute(target)
		if args.tcpscan:
			tcpports = portscan(target,ports,args.tcpscan,args.servicescan)
		if args.icmp:
			ICMPscan(target)
	t2 = datetime.now()
	# Calculates the difference of time, to see how long it took to run the script
	total =  t2 - t1
	# Printing the information to screen
	print 'Scanning Completed in: ', total
def portscan(target,ports,tcp,servicescan):
    #target=IPaddr,ports=list of ports,tcp=true/false,udp=true/false,verbose=true/false
    printmsg(("Now scanning %s" % (target)))
    tcpports=[]
    if tcp:
        for portnum in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.01)
                s.connect((target, portnum))
            except Exception:
                failvar = 0
            else:
		if servicescan:#attempts to get simple service info
			print "%d/tcp \topen"% (portnum),
			if portnum == 80:
				grabHTTP(s)
			else:
				grab(s,target,portnum)
		else:
			print "%d/tcp \topen"% (portnum)
                tcpports.append(portnum)
            s.close()
    printmsg(("%i open TCP ports of %i ports scanned" % (len(tcpports),len(ports))))
    return tcpports

def errormsg(msg): print "[!] Error: %s" % (msg) ; sys.exit(1)
def printmsg(msg): print "[+] lazorScan.py: %s" % (msg)

def iprange(addressrange): # converts a ip range into a list
	list=[]
	first3octets = '.'.join(addressrange.split('-')[0].split('.')[:3]) + '.'
	for i in range(int(addressrange.split('-')[0].split('.')[3]),int(addressrange.split('-')[1])+1):
		list.append(first3octets+str(i))
	return list

def ip2bin(ip):
	b = ""
	inQuads = ip.split(".")
	outQuads = 4
	for q in inQuads:
		if q != "": b += dec2bin(int(q),8); outQuads -= 1
	while outQuads > 0: b += "00000000"; outQuads -= 1
	return b

def dec2bin(n,d=None):
	s = ""
	while n>0:
		if n&1: s = "1"+s
		else: s = "0"+s
		n >>= 1
	if d is not None:
		while len(s)<d: s = "0"+s
	if s == "": s = "0"
	return s

def bin2ip(b):
	ip = ""
	for i in range(0,len(b),8):
		ip += str(int(b[i:i+8],2))+"."
	return ip[:-1]

def returnCIDR(c):
	parts = c.split("/")
	baseIP = ip2bin(parts[0])
	subnet = int(parts[1])
	ips=[]
	if subnet == 32: return bin2ip(baseIP)
	else:
		ipPrefix = baseIP[:-(32-subnet)]
		for i in range(2**(32-subnet)): ips.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
        return ips
def grab(conn,target,portnum):
	try:
		conn.connect((target,portnum))
		ret = conn.recv(1024)#do we get a banner back?
		print '[+]' + str(ret)
		return
	except Exception, e:
		print '[+]' + socket.getservbyport(portnum)#just returns what the port is designated for. may not be accurate
	return
def grabHTTP(conn):
	try:
		conn.send('GET HTTP/1.1 \r\n')
		ret = conn.recv(1024)
		banner = re.search('<address>(.+)</address>',ret)#a bit of regex to extract server info if possible from http request. doesnt always work
		if banner:
			print '[+]' + str(banner.group(1))
		else:
			print '[+]' + str(ret)
		return
	except Exception, e:
		print '[+]' + socket.getservbyport(80)
		return
def traceroute(target):
	try:
		traceroute = subprocess.Popen(["traceroute", target],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)#linux
		for line in iter(traceroute.stdout.readline,""):
		    print line
	except:
		pass
	try:
		traceroute = subprocess.Popen(["tracert", target],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)#windows
		for line in iter(traceroute.stdout.readline,""):
		    print line
	except:
		pass
def ICMPscan(target):
	try:
		icmp = subprocess.Popen(["ping", target, '-c', '1'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		for line in iter(icmp.stdout.readline,""):
		    if "from" in line:
			target = target.rstrip()
		    	print target + " is up."
		    	return 1
	    	else:
	    		return 0
	except:
		pass

if __name__ == '__main__':
    main()
