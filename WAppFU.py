#!/usr/bin/python 

import os
import re
import sys
import time
from argparse import ArgumentParser
import urllib.parse

import utils.heading
import web.webTests
import utils.helper as helper

from web.webTests import webTests
from web.webTests import chromeShot
from web.webTests import goBuster
from web.webTests import msfHTTPAuxilary
from web.webTests import nikto
from web.webTests import dirb
from web.webTests import nmapHTTP

from utils.IDIP import validateHost
from utils.IDIP import getIPAddress
from utils.IDIP import idHosts

from utils.portWork import portScanner

def main():

	# Open File and check for URLs
	urlFile = args.urlFile
	uriList = list()
	try:
		urlSet = set(line.strip() for line in open(urlFile))
		for i in urlSet:
			if i:
				i = i.rstrip('/')
				i += "/"
				uriList.append(i)

		if len(uriList) < 1:
			print ("No Hosts loaded ... Check File:" + urlFile)
			exit()

		helper.whine('\033[94m' + "[*] Loaded  "     + '\033[95m' + str(len(uriList)) + '\033[94m' +  " URL(s)" + '\033[0m')
		'''
		if args.validate:
			# validate the hosts then queue them up
			for uri in uriList:

				# Metasploit needs the host and the port seperate
				match = re.search(r'(http|https)\:\/\/([a-zA-Z0-9.]+)([/]*)', uri)
				if match:
					network = match.group(2)

					# should we validate and only use IP addresses?
					validateHost(network)

				else:
					print("Error identifying network ... " + uri)
		'''
	except IOError:
		print ("Could not read file:"+ urlFile)

	# Rdiscover additional open HTTP ports
	if args.discover:
		uL = list()
		hList = idHosts(uriList)
		for u in hList:
			hstDIR = oDir + "/" + u + "/" 
			if not os.path.exists(hstDIR):
				os.makedirs(hstDIR);
			f = hstDIR + "serviceDisc_"
			uL = portScanner(u,f)
		
		uriList = list(set(uriList + uL))

	# run tests on the final List of URLs
	cURL = 0
	tURL = len(uriList)

	helper.whine('\033[94m' + "[*] Testing " + '\033[95m' + str(len(uriList)) + '\033[94m' +  " URL(s)" + '\033[0m')
	for u in uriList:
		cURL += 1
		port = ""
		helper.whine("\033[94m" + "[*] URL " + '\033[94m' + '\033[95m' + str(cURL) + " of " + str(tURL) + '\033[0m' + "      : "  + '\033[95m' + u + '\033[0m', "debug")
		
		# Get the port from the current URL
		match = re.search(r'(http|https)\:\/\/([a-zA-Z0-9.]+):*([0-9]*)(/*.*)', u)
		if match:
			host = match.group(2)
			if match.group(1) == "http":
				port = "80"
			if match.group(1) == "https":
				port = "443"
			if match.group(3):
				port = match.group(3)

			# We need to make a folder specific for IP
			hstDIR = oDir + "/" + host + "/" 
			if not os.path.exists(hstDIR):
				os.makedirs(hstDIR);
			uri = urllib.parse.quote(match.group(4), safe='')
			OUTFile = hstDIR + uri
			
			# Run ChromShot
			if args.ScreenShot or args.allChecks:
				f = OUTFile + "_screenShot_" + port + ".png"
				chromeShot(u, f)

			# Run Gobuster
			if args.goBuster or args.allChecks:
				f = OUTFile + "_gobuster_vv_" + port + ".txt"
				goBuster(u, f)
			
			# Run dirbuster
			if args.dirb or args.allChecks:			
				f = OUTFile + "_dirb_" + port + ".txt"
				dirb(u, f)
			
			# Metesploit Safe Checks
			if args.msfHTTPAuxilary or args.allChecks:
				f = hstDIR + "_" + port + "_" 
				msfHTTPAuxilary(host,port,f)

			# Run nikto
			if args.nikto or args.allChecks:
				f = OUTFile + "_nikto_" + port + ".txt"
				nikto(u, f)

			# Run nMap HTTP
			if args.nmapHTTP or args.allChecks:
				f = hstDIR + "nMap-HTTP_" + port
				nmapHTTP(host,port,f)


if __name__ == "__main__":
    
    if sys.version_info <= (3, 0):
        sys.stdout.write("This script requires Python 3.x\n")
        sys.exit(1)

    utils.heading.banner()

    # parse all the args
    parser = ArgumentParser(description='Example: python3 %(prog)s --urls ./urlList.txt --all --discover')
    parser.add_argument("-s", "--screenshot",   dest="ScreenShot",    	help="Get ScreenShot",     		action="store_true")
    parser.add_argument("-g", "--gobuster",   	dest="goBuster",    	help="run gobuster",     		action="store_true")
    parser.add_argument("-d", "--dirb",   		dest="dirb",    		help="run dirb",     			action="store_true")
    parser.add_argument("-m", "--msfaux",     	dest="msfHTTPAuxilary", help="run Metesploit HTTP aux",	action="store_true")
    parser.add_argument("-n", "--nikto",     	dest="nikto", 			help="run nikto",				action="store_true")
    parser.add_argument("-e", "--nse",     		dest="nmapHTTP", 		help="run HTTP nse scripts",	action="store_true")
    parser.add_argument("-a", "--all",	 	 	dest="allChecks",		help="All checks",	 			action="store_true")
    
    parser.add_argument("--discover",	dest="discover",  	help="discover http ports",  action="store_true")
    #parser.add_argument("--validate",	dest="validate",  	help="validate IPs",  	action="store_true")
    parser.add_argument("--urls", 		dest="urlFile",  	help="Target URLs")

    args = parser.parse_args()
    if (args.urlFile is None):
        parser.print_help()
        exit()

    if not os.path.isfile(args.urlFile):
        helper.printR("Check File: " + args.urlFile)
        exit()  
    
    # Setup Working directory
    ts = time.strftime("%m%d%Y_%H_%M_%S", time.gmtime())
    oDir = os.path.abspath(os.path.dirname(__file__)) + "/DATA/" + ts
    if not os.path.exists(oDir):
        os.makedirs(oDir);

    main()
    print('')
    helper.printP("Output directory: " + oDir + "/")