import json
import time
import requests
import re
import argparse
import os
import shutil
import subprocess
## Copyright by Stefan Buehler
## Free to use
## Changes must be published in Github

WHITELIST = ["127.0.0.1", "::1", "localhost"]
WHITELIST_REGEX = ""
BLOCKLISTS = {
	'abuse.ch Threatfox(Domain)': {
		'id': 'abusethreatfoxdomain',
		'url':	'https://threatfox.abuse.ch/downloads/hostfile',
		'file' : 'threatfox.domain',
		'address' : {
			"IPV4_ADDR" : "127.0.0.2",
			"IPV6_ADDR" : "::2",
		},
		'enabled': True
	},
	'abuse.ch Urlhaus (Domain)': {
		'id': 'abusezeusdomain',
		'url':	'https://urlhaus.abuse.ch/downloads/hostfile/',
		'file' : 'urlhaus.domain',
		'address' : {
			"IPV4_ADDR" : "127.0.0.3",
			"IPV6_ADDR" : "::3",
		},
		'enabled': True
	},
	'phishtank': {
		'id': 'phishtank',
		'url': 'http://data.phishtank.com/data/[API-KEY]/online-valid.csv',
		'file' : 'phishtank.domain',
		'headers' : {'User-Agent': 'phishtank/[PhistankUser]'},
		'regex': '/^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/',
		'address' : {
			"IPV4_ADDR" : "127.0.0.4",
			"IPV6_ADDR" : "::4",
		},
		'enabled': True
	},
	'blocklist.abuse': {
		'id': 'blocklistabuse',
		'url':	'https://blocklistproject.github.io/Lists/alt-version/abuse-nl.txt',
		'file' : 'blocklist.abuse',
		'address' : {
			"IPV4_ADDR" : "127.0.0.5",
			"IPV6_ADDR" : "::5",
		},
		'enabled': False
	},
	'blocklist.fraud': {
		'id': 'blocklistfraud',
		'url':	'https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt',
		'file' : 'blocklist.fraud',
		'address' : {
			"IPV4_ADDR" : "127.0.0.6",
			"IPV6_ADDR" : "::6",
		},
		'enabled': False
	},
	'blocklist.malware': {
		'id': 'blocklistmalware',
		'url':	'https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt',
		'file' : 'blocklist.malware',
		'address' : {
			"IPV4_ADDR" : "127.0.0.7",
			"IPV6_ADDR" : "::7",
		},
		'enabled': False
	},
	'blocklist.phishing': {
		'id': 'blocklistphishing',
		'url':	'https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt',
		'file' : 'blocklist.phishing',
		'address' : {
			"IPV4_ADDR" : "127.0.0.8",
			"IPV6_ADDR" : "::8",
		},
		'enabled': False
	},
	'blocklist.privacy': {
		'id': 'blocklistprivacy',
		'url':	'https://blocklistproject.github.io/Lists/alt-version/privacy-nl.txt',
		'file' : 'blocklist.privacy',
		'address' : {
			"IPV4_ADDR" : "127.0.0.9",
			"IPV6_ADDR" : "::9",
		},
		'enabled': False
	},
	'blocklist.ransomeware': {
		'id': 'blocklistransomeware',
		'url':	'https://blocklistproject.github.io/Lists/alt-version/ransomeware-nl.txt',
		'file' : 'blocklist.ransomeware',
		'address' : {
			"IPV4_ADDR" : "127.0.0.10",
			"IPV6_ADDR" : "::10",
		},
		'enabled': False
	},
	'blocklist.scam': {
		'id': 'blocklistscam',
		'url':	'https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt',
		'file' : 'blocklist.scam',
		'address' : {
			"IPV4_ADDR" : "127.0.0.11",
			"IPV6_ADDR" : "::11",
		},
		'enabled': False
	},
	'blocklist.tracking': {
		'id': 'blocklisttracking',
		'url':	'https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt',
		'file' : 'blocklist.tracking',
		'address' : {
			"IPV4_ADDR" : "127.0.0.12",
			"IPV6_ADDR" : "::12",
		},
		'enabled': False
	},
	'justdomain.easylist': {
		'id': 'easylist',
		'url':	'https://justdomains.github.io/blocklists/lists/easylist-justdomains.txt',
		'file' : 'justdomain.easylist',
		'address' : {
			"IPV4_ADDR" : "127.0.0.13",
			"IPV6_ADDR" : "::13",
		},
		'enabled': False
	},
	'justdomain.easyprivacy': {
		'id': 'easyprivacy',
		'url':	'https://justdomains.github.io/blocklists/lists/easyprivacy-justdomains.txt',
		'file' : 'justdomain.easyprivacy',
		'address' : {
			"IPV4_ADDR" : "127.0.0.14",
			"IPV6_ADDR" : "::14",
		},
		'enabled': False
	},
	'crazymax.spy': {
		'id': 'crazymaxspy',
		'url':	'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt',
		'file' : 'crazymax.spy',
		'address' : {
			"IPV4_ADDR" : "127.0.0.15",
			"IPV6_ADDR" : "::15",
		},
		'enabled': False
	},
	'crazymax.update': {
		'id': 'crazymaxupdate',
		'url':	'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/update.txt',
		'file' : 'crazymax.update',
		'address' : {
			"IPV4_ADDR" : "127.0.0.16",
			"IPV6_ADDR" : "::16",
		},
		'enabled': False
	},
}



def readWhitelist(path='./whitelist.conf'):
	print('path', path)
	global WHITELIST
	global WHITELIST_REGEX
	print("[READING WHITELIST]")
	try:
		with open(path, 'r') as f:
			whitelist = f.read()
			WHITELIST += whitelist.strip().split()
	except:
		print("[Exception] Whitelist File not found. Proceeding without whitelist")
	WHITELIST_REGEX = re.compile('(?:% s)' % '|'.join(WHITELIST).replace('*','[\w|.]*'))


def is_valid_hostname(hostname):
	if hostname.endswith("."): # A single trailing dot is legal
		hostname = hostname[:-1]
	if len(hostname) > 253:
		return False
	# must be not all-numeric, so that it can't be confused with an ip-address
	if re.match(r"[\d.]+$", hostname):
		return False
	allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	return all(allowed.match(x) for x in hostname.split("."))

def filterAbuseChList(output):
	output = output.replace('\\t', '')
	output = output.replace('127.0.0.1', '')
	listOutput = output.split('\\r\\n')

	escapeCharacters = [ "#", "]", "[", ","]
	listOutput = [x for x in listOutput if not any(ch in x for ch in escapeCharacters)]
	listOutput = list(map(str.strip, listOutput))
	# filtering whitelisted urls
	print("\t[WHITLISTING DATA] File")
	listOutput = [x for x in listOutput if not WHITELIST_REGEX.match(x)]
	#removes blank lines
	listOutput = filter(None, listOutput)
	#remove duplicates
	listOutput = list(set(listOutput))
	#allows only valid hostnames
	listOutput = filter(is_valid_hostname, listOutput)
	return listOutput

def filterJustDomainList(output):
	output = output.replace('\\t', '')
	output = output.replace('\\r', '')
	output = output.replace('127.0.0.1', '')
	listOutput = output.split('\\n')
	escapeCharacters = [ "#", "]", "[", ","]
	listOutput = [x for x in listOutput if not any(ch in x for ch in escapeCharacters)]
	listOutput = list(map(str.strip, listOutput))
	# filtering whitelisted urls
	print("\t[WHITLISTING DATA] File")
	listOutput = [x for x in listOutput if not WHITELIST_REGEX.match(x)]
	#removes blank lines
	listOutput = filter(None, listOutput)
	#remove duplicates
	listOutput = list(set(listOutput))
	#allows only valid hostnames
	listOutput = filter(is_valid_hostname, listOutput)
	return listOutput

def filterCrazyMaxList(output):
	output = output.replace('\\t', '')
	output = output.replace('\\r', '')
	output = output.replace('0.0.0.0', '')
	listOutput = output.split('\\n')
	escapeCharacters = [ "#", "]", "[", ","]
	listOutput = [x for x in listOutput if not any(ch in x for ch in escapeCharacters)]
	listOutput = list(map(str.strip, listOutput))
	# filtering whitelisted urls
	print("\t[WHITLISTING DATA] File")
	listOutput = [x for x in listOutput if not WHITELIST_REGEX.match(x)]
	#removes blank lines
	listOutput = filter(None, listOutput)
	#remove duplicates
	listOutput = list(set(listOutput))
	#allows only valid hostnames
	listOutput = filter(is_valid_hostname, listOutput)
	return listOutput

def filterBlockList(output):
	output = output.replace('\\t', '')
	output = output.replace('\\r', '')
	output = output.replace('127.0.0.1', '')
	listOutput = output.split('\\n')
	escapeCharacters = [ "#", "]", "[", ","]
	listOutput = [x for x in listOutput if not any(ch in x for ch in escapeCharacters)]
	listOutput = list(map(str.strip, listOutput))
	# filtering whitelisted urls
	print("\t[WHITLISTING DATA] File")
	listOutput = [x for x in listOutput if not WHITELIST_REGEX.match(x)]
	#removes blank lines
	listOutput = filter(None, listOutput)
	#remove duplicates
	listOutput = list(set(listOutput))
	#allows only valid hostnames
	listOutput = filter(is_valid_hostname, listOutput)
	return listOutput

def filterPhishtankList(output):
	output = output.replace('\\t', '')
	output = output.replace('\\r', '')
	listOutput = output.split('\\n')
	listOutput = [x.split(',')[1] for x in listOutput[1:] if ',' in x]
	listOutput = [x.split('/')[2] for x in listOutput if len(x.split('/')[2])>2]

	listOutput = list(map(str.strip, listOutput))
	# filtering whitelisted urls
	print("\t[WHITLISTING DATA] File")
	listOutput = [x for x in listOutput if not WHITELIST_REGEX.match(x)]
	#removes blank lines
	listOutput = filter(None, listOutput)
	#remove duplicates
	listOutput = list(set(listOutput))
	#allows only valid hostnames
	listOutput = filter(is_valid_hostname, listOutput)
	return listOutput


def moveFile(filepath):
	filename = filepath.split("/")[-1]
	try:
		shutil.move(os.path.abspath(filepath), os.path.join('/etc/unbound/unbound.conf.d', filename))
	except shutil.SameFileError:
		print("\t[EXCEPTION] Source and destination represents the same file.")
	except PermissionError:
		print("\t[EXCEPTION] Permission denied. Run code as sudo")
	except Exception as e :
		print(e)
		print("\t[EXCEPTION] Error occurred while copying file.")

def verifyUnbound(filepath):
	try:
		output = subprocess.check_output(['/usr/sbin/unbound-checkconf', os.path.abspath(filepath)])
		print("\t[VERIFICATION]     Response", str(output))
		if('no errors' in str(output)): return True
		else:
			os.remove(os.path.abspath(filepath))
			return False
	except PermissionError:
		print("\t[EXCEPTION] Permission denied. Run code as sudo")
	except:
		print("\t[EXCEPTION] Unable to run unbounb-checkconf command. Make sure the command is working.")
	return False

def downloadAndProcessBlocklist(key, obj, location):
	tick = time.time()
	print("\nGETTING DATA FOR: "+str(key))
	headers = obj.get('headers', {'User-Agent': 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/5.0)'})
	response = requests.get(obj['url'], headers = headers)
	contents = response.content

	if('abuse.ch' in key):
		listOutput = filterAbuseChList(str(contents))
	elif('phishtank' in key):
		listOutput = filterPhishtankList(str(contents))
	elif('blocklist' in key):
		listOutput = filterBlockList(str(contents))
	elif('justdomain' in key):
		listOutput = filterJustDomainList(str(contents))
	elif('crazymax' in key):
		listOutput = filterCrazyMaxList(str(contents))


	filepath = location+"blacklist-"+obj['file']+".conf"

	print("\t[DATA RRETRIEVED]  Time: ", round(time.time()-tick,2),"secs")
	print("\t[SAVING DATA]      File: ",obj['file'])
	savefile(listOutput, filepath, obj['address'])
	print("\t[VERIFYING DATA]   Command: unbound-checkconf ")
	verified = verifyUnbound(filepath)
	print("\t[MOVING DATA]      Path:  /etc/unbound/unbound.conf.d/")
	if verified: moveFile(filepath)


def savefile(listOutput, filepath, address):
	try:
		with open(filepath, 'w') as f:
			f.write("server:\n")
			for item in listOutput:
				f.write('local-data: \"')
				f.write("%s" % item)
				f.write(' A ' + address['IPV4_ADDR'] + '\"')
				f.write('\n')

				f.write('local-data: \"')
				f.write("%s" % item)
				f.write(' AAAA ' + address['IPV6_ADDR'] + '\"')
				f.write('\n')
			f.close()
	except IOError as e:
		print(e.reason)

def deletefile(key, obj):
	filepath = '/etc/unbound/unbound.conf.d/'+'blacklist-'+obj['file']+'.conf'
	print(f"[DELETING CONFIG: {obj['file']}] The enabled for {key} is set to false")
	try:
		os.remove(filepath)
	except PermissionError:
		print("\t[EXCEPTION] Permission denied. Run code as sudo")
	except :
		print("\t[EXCEPTION] File is already deleted.")


def restartUnbound():
	try:
		output = subprocess.check_output(['/usr/sbin/service','unbound','reload'])
		print("[RESPONSE] ", str(output))
	except PermissionError:
		print("\t[EXCEPTION] Permission denied. Run code as sudo")



# main
def main():
	parser = argparse.ArgumentParser(description='IP blocklist downloader and importer for pf and ip tables')
	parser.add_argument('-l', '--blocklist_location',help='location to store blocklists', required=False, default='./')
	parser.add_argument('-n', '--blocklist_names',help='specify names of blocklists to download', required=False, default=None, type=lambda s: [str(item) for item in s.split(',')])
	parser.add_argument('-w', '--whitelist',help='specify the path of whitelist.conf file', required=False, default='./whitelist.conf')

	args = parser.parse_args()

	location = args.blocklist_location
	blocknames = args.blocklist_names

	readWhitelist(args.whitelist)

	for key, value in sorted(BLOCKLISTS.items()):
		if value['enabled'] and (not(blocknames) or value['id'] in blocknames):
			downloadAndProcessBlocklist(key, value, location)
		else:
			deletefile(key, value)



	print("[RESTARTING UNBOUND]")
	restartUnbound()


if __name__ == "__main__":
	main()
