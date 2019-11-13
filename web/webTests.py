
import os
import re
import urllib.parse
from shutil import copy2
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.proxy import Proxy, ProxyType

from utils.osWork import muxER
from utils.osWork import muxERquiet
from utils.osWork import realTimeMuxER
from utils.helper import whine

def webTests (urls, o):
	tURL = len(urls)
	cURL = 0
	whine("Running Web Tests on " + str(tURL) + " URL(s)", "info")

def nmapHTTP(host,port,output):
	whine( "nMap HTTP Modules   : " + host + " Port: " + port , "debug")
	cmd = "nmap -Pn --script discovery,vuln,version " + host + " -p " + port + " -oA " + output
	muxERquiet(cmd)

def nikto(url,f):
	whine( "Running nikto       : " + url , "debug")
	cmd = "nikto -Cgidirs all -nointeractive -ask no -maxtime 1h -host " + url + " -Format txt -output " + f
	muxERquiet(cmd)

def dirb(url,f):
	whine( "Running dirb        : " + url , "debug")
	wList = os.path.abspath(os.path.dirname(__file__)) + "/wordlists/master-dirb.txt"
	cmd = "dirb " + url + " " + wList + " -l -o " + f 
	muxERquiet(cmd)

def goBuster(url,f):
	whine( "Running gobuster    : " + url , "debug")
	wList = os.path.abspath(os.path.dirname(__file__)) + "/../web/wordlists/master-gobuster.txt"
	
	# check Verion installed
	cmd = "apt show -a gobuster 2>/dev/null | grep Version"
	r = muxER(cmd)
	mv = re.search(r'Version: 2.*',r)
	if mv:
		f = f.replace("vv", "v2")
		cmd = "gobuster -q -l -k -e -u " + url + " -w " + wList + " -o " + f
	else:
		f = f.replace("vv", "v3")
		cmd = "gobuster dir -q -l -k -e -u " + url + " --wordlist " + wList + " -o " + f
	muxERquiet(cmd)

def chromeShot (url,f,p=""):
	whine( "Taking Screenshot   : " + url , "debug")

	prox = Proxy()
	prox.proxy_type 	= ProxyType.MANUAL
	
	if p:
		prox.proxy_type 	= ProxyType.MANUAL
		prox.http_proxy 	= p
		prox.ssl_proxy 		= p

	capabilities = webdriver.DesiredCapabilities.CHROME
	prox.add_to_capabilities(capabilities)

	chrome_options = Options()
	chrome_options.add_argument("--headless")
	chrome_options.add_argument("--disable-logging")
	chrome_options.add_argument("--log-level=3")
	chrome_options.add_argument("--window-size=1920x1080")
	chrome_options.add_argument("--no-sandbox")
	chrome_options.add_argument("--user-data-dir /tmp")
	chrome_options.add_argument('--ignore-certificate-errors')

	chrome_driver = "/usr/bin/chromedriver"

	# Copy to dedicated screenshot directory
	sDir = os.path.dirname(f)
	sDir = os.path.dirname(sDir)
	sDir += "/ScreenShots/"
	if not os.path.exists(sDir):
		os.makedirs(sDir)
	
	f = sDir + urllib.parse.quote(url, safe='') + ".png"

	try:
		driver = webdriver.Chrome(options=chrome_options, executable_path=chrome_driver, desired_capabilities=capabilities)
		driver.set_page_load_timeout(10)
		driver.get(url)
		driver.get_screenshot_as_file(f)
		# Copy to dedicated screenshot directory
		#copy2(f, sDir)
		driver.quit()
	except Exception as e:
		whine("screenshot Error:" + str(e), "debug")

def msfHTTPAuxilary(host,port,output):
	whine( "Metasploit Modules  : " + host + " Port: " + port , "debug")

	import ast
	import configparser
	config = configparser.ConfigParser()
	msfCFG = os.path.abspath(os.path.dirname(__file__)) + "/../utils/msf.ini"
	whine( "Loading Safe Checks : " + msfCFG, "debug")
	config.read(msfCFG)
	MSF = ast.literal_eval(config.get("MSF-SAFE", "msfLIST"))
	
	r = re.compile(".*http")
	msfLIST = list(filter(r.match, MSF))  
	
	for module in msfLIST:
		m = module.rsplit('/', 1)[-1]
		whine( "Metasploit Module   : " + module, "debug")
		f = output + "_Metasploit_" + m + ".txt"
		cmd = "msfconsole -x \"use  " + module + ";set rhosts " + host + ";set rport " + port + "; run; exit\" > " + f
		muxERquiet(cmd)
