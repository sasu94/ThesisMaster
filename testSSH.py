import paramiko
import time
import re
toVisit=[]
visited=[]
elems={}

class Element:
    def __init__(self,type,name):
        self.type=type
        self.name=name
        self.links=[]
    def addLink(self,link):
        self.links.append(link)

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
	print(curr.type)
	s=text.split("\n")
	name=re.search('Device ID: (.*)',s[1]).group(1)
	ip=re.search('.*: (.*)',s[3]).group(1).strip()
	ports=s[5].split(',')
	fr=re.search('.*: (.*)',ports[0]).group(1)
	to=re.search('.*: (.*)',ports[1]).group(1)
	print(name)
	print(ip)
	print(fr)
	print(to)
	print('--------------')
	print(ip)
	for x in visited:
		print("\t"+x)
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

def main():
	toVisit.append("10.0.2.5")
	visit()
root=Element("Switch","10.0.2.5")
elems["10.0.2.5"]=root
main()
