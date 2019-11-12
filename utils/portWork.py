
import re
from utils.osWork import muxER
import utils.helper as helper

def portScanner (host, file):
	cmd = "nmap -sS -n --randomize-hosts --max-retries 1 -p- --data-length=0 --open " + host + " -oA " + file + " > " + file + ".out"
	muxER(cmd)

	f = file + ".gnmap"
	initPORTs,initURLs = portLandia(f)
	iPORTstr = "|".join(initPORTs)
	cmd = servicABLE(host,initPORTs,f)
	muxER(cmd)
	f = f + ".gnmap"

	# check for updates to the url list
	PORTs,URLs = portLandia(f)
	finalPortList = list(set().union(initPORTs, PORTs))
	finalPortList = sorted(finalPortList, key=int)
	finalPORTstr = "|".join(finalPortList)
	finalUrlList = list(set().union(initURLs, URLs))
	return finalUrlList

def portLandia (file):
	# get all open ports per host
	cmd = "cat " + file + " | grep Ports: " 
	CBH = muxER(cmd)
	
	allPort = set()
	httpList = set()
	H = None

	p = re.search(r'Host: (\d+\.\d+\.\d+\.\d+).*Ports: (.*)',CBH)
	if p:

		H = p.group(1)
		pL = p.group(2).split(',')
		for o in pL:
			# 8834/open/tcp//ssl|http//Nessus vulnerability scanner http UI/
			mo = re.search(r'(\d+)/open/(\w+)/\w*/(\w+)',o)
			if mo: 
				allPort.add(mo.group(1))
				http = re.search(r'(http|https)',o,re.IGNORECASE)
				if http:
					url = http.group(1).lower() + "://" + H + ":" + mo.group(1) + "/"
					httpList.add(url)
					helper.whine("Discovery - Identified URL : " + url, "debug")


	return allPort,httpList

def servicABLE (host,ports,file):
	#helper.whine("Sevice Identification: " + host, "debug")
	pL = ','.join(ports)
	fO = file + ".out"
	cmd = "nmap -sV --max-retries 1 -Pn -p "+ pL + " -T3 --open " + host + " -oA " + file + " > " + fO
	return cmd
