#!/usr/bin/env python3

import requests
import sys
import time
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning


banner = ("""
\033[91m
  ______          __         __           __            
 /_  __/__  _  __/ /_       / /___ ______/ /_____  _____
  / / / _ \| |/_/ __/  __  / / __ `/ ___/ //_/ _ \/ ___/
 / / /  __/>  </ /_   / /_/ / /_/ / /__/ ,< /  __/ /    
/_/  \___/_/|_|\__/   \____/\__,_/\___/_/|_|\___/_/     
                                                        
\033[00m
\033[92mText Injection Scanner by http.deep\033[00m

\033[96m 
Github: https://github.com/ritiksahni
Twitter: https://twitter.com/RitikSahni22
\033[00m
""")

print(banner)
print("======================================")
time.sleep(2)
print("Time started: "+str(datetime.now()))
print("Scanning targets...\n")

# Proof of concept payload.
injection_payload = ("/proofofconcept%2Fcontentspoofing")

requests.packages.urllib3.disable_warnings(InsecureRequestWarning) # Suppresses unverified requests errors.
# Appends the payload in all target domains.
def scan():
	try:
		response = requests.get(target.strip('\n') + injection_payload, verify=False)
		if "contentspoofing" in response.text:
			print("\033[91m" + target.strip('\n') + injection_payload + " IS VULNERABLE!\033[00m")
	except KeyboardInterrupt:
		print('Bye')
		sys.exit()
	except requests.exceptions.ConnectionError:
		print(target.strip('\n') + injection_payload + " ---- CONNECTION ERROR")
	# except ConnectionError:
	# 	print(target.strip('\n') + injection_payload + " - Name resolution error")
	

foundTargets = []

if foundTargets == 0:
	print('No vulnerable websites found!')
	sys.exit()

filepath = open(sys.argv[1], "r")
target_list = filepath.readlines()

for target in target_list:
	scan()