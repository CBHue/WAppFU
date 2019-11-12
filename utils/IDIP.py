#!/usr/bin/python 

import re
import ipaddress
from utils.helper import whine
from utils.osWork import muxER

def getIPAddress (network):
	# Check if this is a hostname
	whine('\033[94m' + "Checking Host   : " + '\033[0m' + network, "status")
	match = re.search(r'[a-zA-Z0-9.]+\.[a-zA-Z]+', network)
	if match:
		whine('\033[94m' + "Lookup Hostname : " + '\033[0m' + network, "status")
		cmd = "nslookup " + network + " | grep Address | tail -1 | cut -d' ' -f2"
		network = muxER(cmd)
		whine('\033[94m' + "IP Addr         : " + '\033[0m' + network, "status")
		
	# Validate the IP
	validateHost(network)

def validateHost (network):
	whine('\033[94m' + "Validating Host : " + '\033[0m' + network, "status")
	cidr = ""

	# Single IP or a network
	match = re.search(r'(\d+.\d+.\d+.\d+)(/\d+)', network)
	if match:
		matchWork = match.group(1)
		whine('\033[94m' + "IP Addr : " + '\033[0m' + matchWork, "status")
		whine('\033[94m' + "Subnet  : " + '\033[0m' + match.group(2), "status")
		cidr = match.group(2)

		if match.group(2) == '/32':
			confirmIP(matchWork, cidr)
		else:
			whine("Expanding network : " + '\033[0m' + network, "status")
			expandedIPList = ipaddress.ip_network(network)
			cidr = "/32"
			for ip in expandedIPList:
				confirmIP(ip, cidr)
	else:
		mHostname = re.search(r'[a-zA-Z0-9.]+\.[a-zA-Z]+', network)
		if mHostname:
			whine('\033[94m' + "Skipping FQDN   : " + '\033[0m' + network, "status")
			return
		whine('\033[94m' + "Single IP       : " + '\033[0m' + network, "status")
		matchWork = network	
		cidr = "/32"
		confirmIP(matchWork, cidr)

def confirmIP (matchWork, cidr):	
	# Lets see if this is a real IP
	try:
		ipaddress.ip_address(matchWork)
		
		# Add hosts to DB
		h = str(matchWork) + cidr
		#print(h)

		# Add the host to a list
		
		return True
	except ValueError:
		printR("Address/Netmask is invalid: "+ '\033[0m' + matchWork + cidr)
		return False
	except Exception as e:
		whine('[validateHost] ' + str(e) + " " + str(matchWork), "error")
		return False

def idHosts(uriList):
	hostSet = set()

	for uri in uriList:
		match = re.search(r'(http|https)\:\/\/([a-zA-Z0-9.]+):*([0-9]*)(/*.*)', uri)
		if match:
			host = match.group(2)
			'''
			port = match.group(3)
			if not port:
				if match.group(1) == "http":
					port = "80"
				if match.group(1) == "https":
					port = "443"
			uniq = host + ":" + port
			hostSet.add(uniq)
			'''
			hostSet.add(host)
	# return final host list
	hostList = [i for i in hostSet if i] 
	return hostList