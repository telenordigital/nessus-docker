#!/usr/bin/env python

## DEPRECATED
## This script is currently not working, and is here in the hopes that it will be fixed at one point.
##
## Script to download a specified deb package from Tenable's website.

import json, urllib2, hashlib, re, os, sys

# Get the current working directory
cwd = os.path.dirname(os.path.abspath(__file__))

# "Spoof" the header to get around user-agent block
hdrs = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101 Firefox/59.0",
}
request = urllib2.Request('https://www.tenable.com/plugins/os.json', headers = hdrs)

# First we need to get the version data
data = json.loads(urllib2.urlopen(request).read())

# If the user just requested what the current Nessus version is, spit it out and bail.
if len(sys.argv) > 1 and sys.argv[1] == 'version':
	print data['version']
	exit(0)

# Now we need to find the Ubuntu 16.04 Nessus package from the JSON file.
for opsys in data['categories']:
	if opsys['name'] == 'Linux':
		for package in opsys['files']:
			if package['type'] == 'nessus' and package['os'] == 'ubuntu1110' and package['arch'] == 'x64':
				nessus = package

# Next, lets get the download token from the page
request = urllib2.Request('https://www.tenable.com/products/nessus/select-your-operating-system', headers = hdrs)
token = re.findall(
	r'<div id="timecheck" class="hidden">([\w\d]+)</div>',
	urllib2.urlopen(request).read()
)[0]


# Now lets download the file and save it to a known location
duri = 'http://downloads.nessus.org/nessus3dl.php?file={}&licence_accept=yes&t={}'.format(nessus['file'],token)
request = urllib2.Request(duri, headers = hdrs)
with open(os.path.join(cwd, 'Nessus.deb'), 'wb') as deb:
	deb.write(urllib2.urlopen(request).read())

# And lastly, lets verify that the download worked
filehash = hashlib.sha256()
with open(os.path.join(cwd, 'Nessus.deb')) as deb:
	filehash.update(deb.read())
if filehash.hexdigest() != nessus['sha256']:
	print 'Download Verification Failed!'
	exit(1)
else:
	print 'Nessus Version: {}\nDownloaded DEB: {} as Nessus.deb'.format(data['version'], nessus['file'])
