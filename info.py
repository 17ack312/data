import bane
import nmap
import os
import sys
import requests, urllib3, ssl
import socket

import warnings
warnings.filterwarnings("ignore")


def check_wp(url):
	url = "https://wordpress-crawler.p.rapidapi.com/check/"
	querystring = {"url":url}
	headers = {"X-RapidAPI-Host": "wordpress-crawler.p.rapidapi.com",
	"X-RapidAPI-Key": "6be506998emshd0400186b034514p11bc21jsnbcd08c437c02"}
	response = requests.request("GET", url, headers=headers, params=querystring)
	print(response.text)

def _scan(ip, arg):
	nm=nmap.PortScanner()
	res=nm.scan(hosts=ip, arguments=arg)['scan']
	for i in res.keys():
		res = res[i]
	return res

def get_status(host):
	stat=(os.popen('curl -LsI --connect-timeout 5 "'+host+'"').read().split('\n')[0].strip().split(' ',1)[-1].split(' ',1)[0].strip())
	"""
	context = ssl._create_unverified_context()
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	res = requests.get(host, verify=False,timeout=5).status_code
	print(host,res)
	"""
	return stat

def get_url(ip,hostnames):
	urls=[]
	data=[ip]+hostnames
	for d in data:
		link=('https://'+d)
		stat=(os.popen('curl -LsI --connect-timeout 5 "'+link+'"').read().split('\n')[0].strip().split(' ',1)[-1].split(' ',1)[0].strip())
		if stat=='200' or stat=='301':
			urls.append(link)
			res=bane.crawl(link, timeout=10 )
			for r in range(len(res)-1):
				urls.append(link)
				res=bane.crawl(link, timeout=10 )
				for r in range(len(res)-1):
					urls.append(res[r][1])
		else:
			link=link.replace('https://','http://',1)
			stat=(os.popen('curl -LsI --connect-timeout 5 "'+link+'"').read().split('\n')[0].strip().split(' ',1)[-1].split(' ',1)[0].strip())
			if stat=='200' or stat=='301':
				urls.append(link)
				res=bane.crawl(link, timeout=10 )
				for r in range(len(res)-1):
					urls.append(res[r][1])

		for i in [80,443,3389,8080,8443,8888]:
			link=link=('https://'+d+':'+str(i))
			stat=(os.popen('curl -LsI --connect-timeout 5 "'+link+'"').read().split('\n')[0].strip().split(' ',1)[-1].split(' ',1)[0].strip())
			if stat=='200' or stat=='301':
				urls.append(link)
				res=bane.crawl(link, timeout=10 )
				for r in range(len(res)-1):
					urls.append(res[r][1])
			else:
				link=link.replace('https://','http://',1)
				stat=(os.popen('curl -LsI --connect-timeout 5 "'+link+'"').read().split('\n')[0].strip().split(' ',1)[-1].split(' ',1)[0].strip())
				if stat=='200' or stat=='301':
					urls.append(link)
					res=bane.crawl(link, timeout=10 )
					for r in range(len(res)-1):
						urls.append(res[r][1])

	urls=list(set(urls))
	return urls

	
#print(bane.get_banner('162.214.80.73' , p=80 , payload=None , timeout=5 ))
#link=sys.argv[1]




		
#get_IP(sys.argv[1])
#get_hostnames(sys.argv[1])
#socket.gethostbyaddr('162.214.80.73')
#print(bane.reverse_ip_lookup(sys.argv[1]))

#res=bane.xss_forms(link , payload="<script>alert(123)</script>" , timeout=15 )
#res=bane.path_traversal_urls(link, timeout=15 )
#res=bane.hsts(link, timeout=15 )
#res=bane.cors_misconfigurations(link, timeout=15 )

#res=bane.http()
#res=bane.forms_parser(link , timeout=10 )
#res=bane.inputs(link , value=True , timeout=10 )
#res=bane.crawl(link , timeout=10 )
#res=bane.subdomains_extract(link , timeout=10 )


#res=bane.get_banner(IP , p='443' , payload=None , timeout=5 )
#res=bane.myip()

#es=bane.norton_rate(link , timeout=15 )
#res=bane.headers( link )
#res=bane.reverse_ip_lookup( IP )
#res=bane.resolve( domain , server="8.8.8.8" )


#get_url('65.1.243.117',['ec2-65-1-243-117.ap-south-1.compute.amazonaws.com', 'nshm.com'])