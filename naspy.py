import paramiko
import time
import re
import json
import pyshark
import sys
import json
import os
from cryptography.fernet import Fernet

toVisit=[]
visited=[]
elems={}
db={}

class Element:
    def __init__(self,type,name,platform,ip):
        self.type=type
        self.name=name
        self.platform=platform
        self.ip=ip
        self.mac=''
        self.links=[]
    def addMac(self,mac):
        self.mac=mac
    def addLink(self,link):
        self.links.append(link)
    def toJSON(self):
        return json.dumps(self,default=lambda o:o.__dict__)

class Link:
    def __init__(self,port1,port2,element):
        self.port1=port1
        self.port2=port2
        self.element=element
        
        
def decryptdb():    
    key=os.environ.get('KEY')
    fernet = Fernet(key)


    with open('hosts.db', 'rb') as f:
        data = f.read()

    db=json.loads(data.decode())


    for ip in db:
        password=db[ip]['pass']
        enable=db[ip]['en']
        
        db[ip]['pass']=fernet.decrypt(password.encode()).decode()
        db[ip]['en']=fernet.decrypt(enable.encode()).decode()
        
    return db
def connectionSSH(ip, user, password):
    list=[]
    try:
            
        client=paramiko.SSHClient()
        if ip not in db:
           return
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=ip,username=db[ip]['user'],password=db[ip]['pass'])

        sh=client.invoke_shell()
        sh.send("en\n")
        sh.send(db[ip]['en']+"\n")
        sh.send("terminal length 0\n")
        sh.send("show lldp neighbors detail\n")
        sh.send("\n")
        buff=''
        while not re.search('.*#\r\n.*#.*',buff):
            if sh.recv_ready():
                resp = sh.recv(9999).decode('ascii')    
                # code won't stuck here
                buff+=resp

        if re.search('.*LLDP.*not.*',buff):
            buff=''
            sh.send("show cdp neighbors detail\n")
            sh.send("\n")
            while not re.search('.*#\r\n.*#.*',buff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')    
                    # code won't stuck here
                    buff+=resp
        
        cdp=re.compile('--+').split(buff)[1:]
        
        
        buff=''
        sh.send("show ip arp\n")
        sh.send("\n");
        
        while not re.search('.*#\r\n.*#.*',buff):
            if sh.recv_ready():
                resp = sh.recv(9999).decode('ascii')    
                # code won't stuck here
                buff+=resp
    
        
        sh.send("exit\r\n")
        
        arp=buff.split("\n")
        list=(cdp,arp[2:(len(arp)-2)])
        
    finally:
        client.close()
        return(list)


def parseCDP(text,curr):
    #print(text)

    s=text.split("\n")
    name=re.search('Device ID: (.*)',s[1]).group(1).strip()
    ip=re.search('.*IP address: (.*)',s[3]).group(1).strip()
    ports=s[5].split(',')
    fr=re.search('.*: (.*)',ports[0]).group(1).strip()
    to=re.search('.*: (.*)',ports[1]).group(1).strip()
    info=s[4].split(',')
    plat=re.search('.*Platform: (.*)',info[0]).group(1).strip()
    capa=re.search('.*Capabilities: (.*)',info[1]).group(1).strip()
    #print(name)
    #print(ip)
    #print(fr)
    #print(to)
    #print(plat)
    #print(capa)
    #print('--------------')
    
    
    if ip in elems:
        element=elems[ip]
        if element.type=='Unknown':
            element.type=capa
        if element.platform=='Unknown':
            element.platform=platform
        if element.name=='Unknown':
            element.name=name       
        
        
    else:
        element=Element(capa,name,plat,ip)
        elems[ip]=element
    curr.addLink(Link(fr,to,element))
    
    if(ip not in visited and ip not in toVisit):
        toVisit.append(ip)
        
        
def parseArp(text,curr):

    text=re.compile('\s\s+').split(text)
    ip=text[1]
    mac=text[3]
    
    if ip in elems:
        print(ip+" "+elems[ip].ip+" "+mac)
        
        elems[ip].addMac(mac)
        

def visit():
    while(toVisit):
        ip=toVisit.pop(0)
        print("\ntrying to connect to: "+ip+"\n")
        list=connectionSSH(ip,"test","ciao")
        if not list:
            print("unable to connect in ssh\n")
        else:
            curr=elems[ip]
            for text in list[0]:
                parseCDP(text,curr)
            for text in list[1]:
                print(text)
                parseArp(text,curr)
            print('links found for '+ip+': '+str(len(curr.links)))
        visited.append(ip)
        
def constructJSON():
    
    first=True
    firstE=True
    nodes='{"nodes":\n\t['
    edges='"edges":\n\t['
    cont=0
    computed=[]
    
    
    
    for ip in sorted(elems.keys()):
        if first:
            nodes+='{"id":"'+ip+'", "label":"'+elems[ip].name+'","x":0,"y":0,"size":1,"mac":"'+elems[ip].mac+'"}'
            first=False
        else:
            nodes+=',\n\t{"id":"'+ip+'", "label":"'+elems[ip].name+'","x":0,"y":1,"size":1,"mac":"'+elems[ip].mac+'"}'
        for edge in elems[ip].links:
            if((edge.port1,edge.port2) not in computed and (edge.port2, edge.port1) not in computed):
                if firstE:
                    edges+='{"id":'+ str(cont) +', "source":"'+ip+'", "target": "'+edge.element.ip+'","from":"'+edge.port1+'", "to":"'+edge.port2+'"}'
                    firstE=False
                    computed.append((edge.port1, edge.port2))
                else:
                    edges+=',\n\t{"id":'+ str(cont) +', "source":"'+ip+'", "target": "'+edge.element.ip+'","from":"'+edge.port1+'", "to":"'+edge.port2+'"}'
                    computed.append((edge.port1, edge.port2))
                cont+=1
    nodes+=']\n,'
    edges+=']\n}'
    
    
    s=nodes+edges
    return s

def sniff(timeout):
    try:
        print("start sniffing\n")
        cap=pyshark.LiveCapture('eth0',display_filter='cdp')
        cap.sniff(packet_count=1,timeout=timeout)
        if cap:
            pack=cap[0]
            id=pack.cdp.deviceid
            ip=pack.cdp.nrgyz_ip_address
            capa=pack.cdp.capabilities
            platform=pack.cdp.platform
            root=Element(capa,id,platform,ip)
            elems[ip]=root
            toVisit.append(ip)
            db=decryptdb()
            visit()
            #print(constructJSON(root))
        else:
            print("time expired")
    finally:
        print()
        #cap.close()

if len(sys.argv)>1:
    if sys.argv[1]=="-a" and len(sys.argv)==3:
        sniff(int(sys.argv[2]))
    elif sys.argv[1]=="-a":
        sniff(180)
    elif sys.argv[1]=="-m" and len(sys.argv)==3:
        ip=sys.argv[2]
        root=Element("Unknown","Unknown","unknown",ip)
        elems[ip]=root
        toVisit.append(ip)
        db=decryptdb()
        visit()
        #constructJSON(root)
    else:
        print("usage: naspy.py -a [timeout] for automatic sniff of cdp packet (180s default)\ntestSSH.py -m ip for manual search")
else:
    print("usage: nas.py -a [timeout] for automatic sniff of cdp packet (180s default)\ntestSSH.py -m ip for manual search")

file = open('Webpage/data.json','w')

file.write(constructJSON())
file.close()