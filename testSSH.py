import paramiko
import time
import re
import json
import pyshark

toVisit=[]
visited=[]
elems={}

class Element:
	def __init__(self,type,name,platform):
		self.type=type
		self.name=name
		self.platform=platform
		self.links=[]
	def addLink(self,link):
		self.links.append(link)
	def toJSON(self):
		return json.dumps(self,default=lambda o:o.__dict__)

class Link:
    def __init__(self,port1,port2,element):
        self.port1=port1
        self.port2=port2
        self.element=element

def connectionSSH(ip, user, password):
	list=[]
	try:
		client=paramiko.SSHClient()
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		client.connect(hostname=ip,username=user,password=password)

		sh=client.invoke_shell()
		sh.send("en\r\n")
		sh.send("ciao\r\n")
		sh.send("terminal length 0\r\n")
		sh.send("show cdp neighbors detail\r\n")
		sh.send("exit\r\n")
		time.sleep(1)
		out=sh.recv(65535)
		
		client.close()

		list=re.compile('--+').split(out.decode('ascii'))

		
	finally:
		return(list)


def parse(text,curr):
	print(text)

	s=text.split("\n")
	name=re.search('Device ID: (.*)',s[1]).group(1)
	ip=re.search('.*IP address: (.*)',s[3]).group(1).strip()
	ports=s[5].split(',')
	fr=re.search('.*: (.*)',ports[0]).group(1)
	to=re.search('.*: (.*)',ports[1]).group(1)
	info=s[4].split(',')
	plat=re.search('.*Platform: (.*)',info[0]).group(1)
	capa=re.search('.*Capabilities: (.*)',info[1]).group(1).strip()
	print(name)
	print(ip)
	print(fr)
	print(to)
	print(plat)
	print(capa)
	print('--------------')
	print(ip)
	
	element=Element(name,capa,plat)
	elems[ip]=element
	curr.addLink(Link(fr,to,element))
	
	if(ip not in visited and ip not in toVisit):
		toVisit.append(ip)

def visit():
	while(toVisit):
		ip=toVisit.pop(0)
		print("\ntrying to connect to: "+ip+"\n")
		list=connectionSSH(ip,"test","ciao")
		if not list:
			print("unable to connect in ssh\n")
		else:
			curr=elems[ip]
			list=list[1:]
			for text in list:
				parse(text,curr)
		visited.append(ip)

def sniff():
	cap=pyshark.LiveCapture('eth0',display_filter='cdp')
	packet=cap.sniff_continuously(packet_count=1)
	print(packet[0])
	print("\n\n")
	cap.close()

def main():
	toVisit.append("10.0.2.5")
	#visit()
	sniff()

root=Element("Switch","10.0.2.5","cacca")
elems["10.0.2.5"]=root
main()
