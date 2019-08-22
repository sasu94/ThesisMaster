import paramiko
import time
import re
import json
import pyshark
import sys
import json
import os
import difflib
from cryptography.fernet import Fernet

toVisit=[]
visited=[]
elems={}
elemsByMac={}

class Element:
    def __init__(self,type,name,platform,ip):
        self.type=type
        self.name=name
        self.platform=platform
        self.ip=ip
        self.mac=''
        self.links=[]
        
    def __eq__(self, other):
        return self.ip == other.ip

    def __hash__(self):
        return hash(self.ip_address)

    
    def addMac(self,mac):
        self.mac=mac
    def addLink(self,link):
        self.links.append(link)
    def toJSON(self):
        return json.dumps(self,default=lambda o:o.__dict__)
    def connectionSSH(self,db):
        print("\ntrying to connect to: "+self.ip+"\n\nunable to connect to SSH")
    
    
class CiscoElement(Element):
    def connectionSSH(self,db):
        list=[]
        ip=self.ip
        count=0
        print("\ntrying to connect to: "+self.ip+"\n")
        try:
            client=paramiko.SSHClient()
            if ip not in db:
                print('unable to connect to SSH')
                return
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=ip,username=db[ip]['user'],password=db[ip]['pass'])

            sh=client.invoke_shell()
            sh.send("en\n")
            sh.send(db[ip]['en']+"\n")
            sh.send("terminal length 0\n")
            sh.send("show lldp neighbors detail\n")
            sh.send("\n")
            lldpbuff=''
           
            while not re.search('.*#\r\n.*#.*',lldpbuff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')    
                    lldpbuff+=resp
            
            lldp=[]
            if not re.search('.*LLDP.*not.*',lldpbuff):
                lldp=re.compile('--+').split(lldpbuff)[1:]
            
            
            for text in lldp:
                if self.parseLLDP(text):
                    count+=1
                
            cdpbuff=''
            sh.send("show cdp neighbors detail\n")
            sh.send("\n")
            while not re.search('.*#\r\n.*#.*',cdpbuff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')    
                    cdpbuff+=resp
            cdp=[]
            if not re.search('.*CDP.*not.*',lldpbuff):
                cdp=re.compile('--+').split(cdpbuff)[1:]
            
            for text in cdp:
                if self.parseCDP(text):
                    count+=1
            
            buff=''
            sh.send("show ip arp\n")
            sh.send("\n");
            
            while not re.search('.*#\r\n.*#.*',buff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')    
                    # code won't stuck here
                    buff+=resp

            
            arp=buff.split("\n")
            arp=arp[2:(len(arp)-2)]
            
            for text in arp:
                if self.parseArp(text):
                    count+=1
            
            buff=''
            sh.send("show mac address-table\n")
            sh.send("\n");
            
            while not re.search('.*#\r\n.*#.*',buff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')    
                    # code won't stuck here
                    buff+=resp

            
            sh.send("exit\r\n")
            
            mac_table=buff.split("\n")
            mac_table=mac_table[6:(len(mac_table)-3)]
            
            count+=self.parseMacTable(mac_table)
            
            print('links found for '+self.ip+': '+str(count))
           
        except:
            print('unable to connect to SSH')
        finally:
            client.close()
        
    def parseCDP(self, text):
        added=False  
        try:       
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
                if plat.__contains__('Cisco'):
                    element=CiscoElement(capa,name,plat,ip)
                elif plat.__contains__('Extreme'):
                    element=ExtremeElement(capa,name,plat,ip)
                else:
                    element=Element(capa,name,plat,ip)
                elems[ip]=element
                
            l=Link(fr,to,element)
            
            if l not in self.links:
                added=True
                self.addLink(l)
            
            if(ip not in visited and ip not in toVisit):
                #print('added to visit from cdp '+element.ip)
                toVisit.append(ip)
        except:
            print('found new element but not enough information to be added\n')
        finally:
            return added
            
    def parseLLDP(self,text):
        
        added=False
        try:
            s=text.split("\n")
            
            name=ip=fr=to=capa=plat='Unknown'
            
            for t in s:
                if re.search('System Name: (.*)',t):
                    name=re.search('System Name: (.*)',t).group(1).strip()
                elif re.search('.*IP: (.*)',t):
                    ip=re.search('.*IP: (.*)',t).group(1).strip()
                elif re.search('Local Intf: (.*)',t):
                    fr=re.search('Local Intf: (.*)',t).group(1).strip()
                elif re.search('Port id: (.*)',t):
                    to=re.search('.*: (.*)',t).group(1).strip()
                elif re.search('.*System Capabilities: (.*)',t):
                    capa=re.search('.*System Capabilities: (.*)',t).group(1).strip()
                elif re.search('.*System Description: (.*)',t):
                    plat=s[s.index(t)+1].strip()
            
        #    print(name)
        #    print(ip)
        #    print(fr)
        #    print(to)
        #    print(plat)
        #    print(capa)
        #    print('--------------')
            
            if ip in elems:
                element=elems[ip]
                if element.type=='Unknown':
                    element.type=capa
                if element.platform=='Unknown':
                    element.platform=plat
                if element.name=='Unknown':
                    element.name=name         
            else:
                if plat.__contains__('Cisco'):
                    element=CiscoElement(capa,name,plat,ip)
                elif plat.__contains__('Extreme'):
                    element=ExtremeElement(capa,name,plat,ip)
                else:
                    element=Element(capa,name,plat,ip)
                elems[ip]=element
                
            l=Link(fr,to,element)
            
            if l not in self.links:
                added=True
                self.addLink(l)
            
            if(ip not in visited and ip not in toVisit):
                #print('added to visit from lldp '+element.ip)
                toVisit.append(ip)
        except:
            print('found new element but not enough information to be added\n')
        finally:
            return added
            
            
    def parseArp(self,text):

        text=re.compile('\s\s+').split(text)
        ip=text[1]
        mac=text[3]
        
        element=None
        
        if ip in elems:
            element=elems[ip]
        else:
            element=Element("Unknown","Unknown","unknown",ip)
            elems[ip]=element
            
        element.addMac(mac)
        
        elemsByMac[mac]=element

    def parseMacTable(self, text):
        
        added=0
        single_occurrences=[]
        
        
        for i in range(len(text)):
            r1=re.compile('\s\s+').split(text[i])
            found=False
            for j in range(len(text)):
                r2=re.compile('\s\s+').split(text[j])
                if(r1[4]==r2[4] and r1[2]!=r2[2]):
                    found=True
            if not found:
                single_occurrences.append(r1)
                
        for entry in single_occurrences:
            if entry[2] in elemsByMac:
                element=elemsByMac[entry[2]]
                
                l=Link(entry[4].strip(),'Unknown',element)
                
                if l not in self.links:
                    added+=1
                    self.addLink(l)
                
                if(element.ip not in visited and element.ip not in toVisit):
                    #print('added to visit from mac '+element.ip)
                    toVisit.append(element.ip)
        
        return added
        

class ExtremeElement(Element):
    def connectionSSH(self,db):
        list=[]
        ip=self.ip
        count=0
        print("\ntrying to connect to: "+self.ip+"\n")
        try:
            client=paramiko.SSHClient()
            if ip not in db:
                return
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=ip,username=db[ip]['user'],password=db[ip]['pass'])
            
            sh=client.invoke_shell()
            sh.send("disable clipaging\n")
            sh.send("show lldp neighbors detailed\n")
            sh.send("\n")
            lldpbuff=''
            while not re.search('.*# \r\n.*#',lldpbuff):
                if sh.recv_ready():
                    resp = sh.recv(9999)
                    lldpbuff+=resp.decode('ascii')
            
            lldp=[]
            if not re.search('.*LLDP.*not.*',lldpbuff):
                lldp=re.compile('--+').split(lldpbuff)[1:]
                
            for text in lldp:
                if self.parseLLDP(text):
                    count+=1
                    
            print('count after lldp '+str(count))
            
            cdpbuff=''
            sh.send("show cdp neighbor detail\n")
            sh.send("\n")
            while not re.search('.*# \r\n.*#.*',cdpbuff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')    
                    cdpbuff+=resp
            cdp=[]
            if not re.search('.*CDP.*not.*',lldpbuff):
                cdp=re.compile('--+').split(cdpbuff)[1:]
            
            
            buff=''
            sh.send("show iparp\n")
            sh.send("\n");
            
            while not re.search('.*# \r\n.*#.*',buff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')    
                    # code won't stuck here
                    buff+=resp

            
            arp=buff.split("\n")
            arp=arp[2:(len(arp)-2)]
            
            buff=''
            sh.send("show fdb\n")
            sh.send("\n");
            
            while not re.search('.*# \r\n.*#.*',buff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')    
                    # code won't stuck here
                    buff+=resp

            
            sh.send("exit\r\n")
            
            mac_table=buff.split("\n")
            mac_table=mac_table[6:(len(mac_table)-3)]
            
            list=(cdp,arp,lldp,mac_table)
           
        except:
            print('unable to connect to SSH')
        finally:
            client.close()
            return(list)
        
    def parseCDP(self,text):
        added=False  
        try:       
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
                if plat.__contains__('Cisco'):
                    element=CiscoElement(capa,name,plat,ip)
                elif plat.__contains__('Extreme'):
                    element=ExtremeElement(capa,name,plat,ip)
                else:
                    element=Element(capa,name,plat,ip)
                elems[ip]=element
                
            l=Link(fr,to,element)
            
            if l not in curr.links:
                added=True
                curr.addLink(l)
            
            if(ip not in visited and ip not in toVisit):
                #print('added to visit from cdp '+element.ip)
                toVisit.append(ip)
        except:
            print('found new element but not enough information to be added\n')
        finally:
            return added
            
    def parseLLDP(self, text):
        print(text)
        added=False
        try:
            s=text.split("\n")
            
            name=ip=fr=to=capa=plat='Unknown'
            
            for t in s:
                if re.search('System Name: (.*)',t):
                    name=re.search('System Name: "(.*)"',t).group(1).strip()
                elif re.search('.*Management Address\s+: (.*)',t):
                    ip=re.search('.*Management Address.*: (.*)',t).group(1).strip()
                elif re.search('LLDP (.*) detected.*',t):
                    fr=re.search('LLDP (.*) detected.*',t).group(1).strip()
                elif re.search('Port ID\s+: (.*)',t):
                    to=re.search('.*: "(.*)"',t).group(1).strip()
                elif re.search('.*System Capabilities : (.*)',t):
                    capa=re.search('.*System Capabilities : "(.*)"',t).group(1).strip()
                elif re.search('.*System Description: (.*)',t):
                    plat=re.search('.*System Description: (.*)',t).group(1).strip()
                    index=s.index(t)+1
                    while not re.search('.*Port Description: (.*)',s[index]):
                        plat+=s[index].strip()
                        index+=1
                    plat=plat[1:len(plat)-2]
            
#            print(name)
#            print(ip)
#            print(fr)
#            print(to)
#            print(plat)
#            print(capa)
#            print('--------------')
            
            if ip in elems:
                element=elems[ip]
                if element.type=='Unknown':
                    element.type=capa
                if element.platform=='Unknown':
                    element.platform=plat
                if element.name=='Unknown':
                    element.name=name         
            else:
                if plat.__contains__('Cisco'):
                    element=CiscoElement(capa,name,plat,ip)
                elif plat.__contains__('Extreme'):
                    element=ExtremeElement(capa,name,plat,ip)
                else:
                    element=Element(capa,name,plat,ip)
                elems[ip]=element
                
            l=Link(fr,to,element)
            
            if l not in self.links:
                added=True
                self.addLink(l)
            
            if(ip not in visited and ip not in toVisit):
                #print('added to visit from lldp '+element.ip)
                toVisit.append(ip)
        except:
            print('found new element but not enough information to be added')
        finally:
            return added
            
            
    def parseArp(self,text):

        text=re.compile('\s\s+').split(text)
        ip=text[1]
        mac=text[3]
        
        element=None
        
        if ip in elems:
            element=elems[ip]
        else:
            element=Element("Unknown","Unknown","unknown",ip)
            elems[ip]=element
            
        element.addMac(mac)
        
        elemsByMac[mac]=element

    def parseMacTable(self, text):
        
        added=0
        single_occurrences=[]
        
        
        for i in range(len(text)):
            r1=re.compile('\s\s+').split(text[i])
            found=False
            for j in range(len(text)):
                r2=re.compile('\s\s+').split(text[j])
                if(r1[4]==r2[4] and r1[2]!=r2[2]):
                    found=True
            if not found:
                single_occurrences.append(r1)
                
        for entry in single_occurrences:
            if entry[2] in elemsByMac:
                element=elemsByMac[entry[2]]
                l=Link(entry[4].strip(),'Unknown',element)
                
                if l not in curr.links:
                    added+=1
                    curr.addLink(l)
                
                if(element.ip not in visited and element.ip not in toVisit):
                    #print('added to visit from mac '+element.ip)
                    toVisit.append(element.ip)
        
        return added



class Link:
    def __init__(self,port1,port2,element):
        self.port1=port1
        self.port2=port2
        self.element=element
        
    def __eq__(self, other):
        return self.element == other.element

    def __hash__(self):
        return hash(self.element.ip)

        
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

def visit():
    db=decryptdb()
    while(toVisit):
        ip=toVisit.pop(0)
        element=elems[ip]
        element.connectionSSH(db)
        visited.append(ip)
        
    constructJSON()
        
def constructJSON():
    
    first=True
    firstE=True
    nodes='{"nodes":[\n\t'
    edges='"edges":[\n\t'
    cont=0
    computed=[]
    
    
    
    for ip in sorted(elems.keys()):
        if first:
            nodes+='{"id":"'+ip+'", "label":"'+elems[ip].name+'","x":0,"y":0,"size":1,"mac":"'+elems[ip].mac+'"}'
            first=False
        else:
            nodes+=',\n\t{"id":"'+ip+'", "label":"'+elems[ip].name+'","x":0,"y":1,"size":1,"mac":"'+elems[ip].mac+'"}'
        for edge in elems[ip].links:
            if((ip,edge.element.ip) not in computed and (edge.element.ip, ip) not in computed):
                if firstE:
                    edges+='{"id":'+ str(cont) +', "source":"'+ip+'", "target": "'+edge.element.ip+'","from":"'+edge.port1+'", "to":"'+edge.port2+'"}'
                    firstE=False
                else:
                    edges+=',\n\t{"id":'+ str(cont) +', "source":"'+ip+'", "target": "'+edge.element.ip+'","from":"'+edge.port1+'", "to":"'+edge.port2+'"}'
                computed.append((ip,edge.element.ip))
                cont+=1

    nodes+='\n],'
    edges+='\n]}'
    
    
    s=nodes+edges
    
    nF=s.split('\n')
    #element=nF[2][:7]+'"2'+nF[2][9:]
    #element2=nF[3][:7]+'"2'+nF[3][9:]
    #nF.insert(2,element)
    #nF.insert(4,element2)
    with open('Webpage/data.json') as f2:
        oldFile=f2.read()

    newElements=[]
    for line in list(difflib.unified_diff(oldFile.split('\n'), nF, fromfile='oldFile', tofile='newFile',lineterm="\n"))[2:]:
        end=0
        if line[len(line)-1]==',':
            end=len(line)-2
        else:
            end=len(line)-1
    
        if line.__contains__('{'):
            if line[0]=='+':
                newElements.append(line[1:end]+', "new":"true"}')
            if line[0]=='-':
                newElements.append(line[1:end]+', "new":"false"}')
      
    
    toRemove=[]
    for i in range(len(newElements)):
        je1=json.loads(newElements[i])
        if 'source' in je1:
            toRemove.append(newElements[i])
        for j in range (i+1,len(newElements)):
            print(newElements[j])
            je2=json.loads(newElements[j])
            if(je1['id']==je2['id'] and je1['new']!=je2['new']):
                if newElements[i] not in toRemove:
                    toRemove.append(newElements[i])
                if newElements[j] not in toRemove:
                    toRemove.append(newElements[j])
       
    for i in toRemove:
        if i in newElements:
            newElements.remove(i)
      
    diffFile='{"items":['+",\n".join(newElements)+']}'


    with open('Webpage/diff.json','w+') as d:
        d.write(diffFile)
             
    with open('Webpage/data.json','w') as file:
        file.write("\n".join(nF))

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
            visit()
        else:
            print("time expired")
    finally:
        cap.close()

if len(sys.argv)>1:
    if sys.argv[1]=="-a" and len(sys.argv)==3:
        sniff(int(sys.argv[2]))
    elif sys.argv[1]=="-a":
        sniff(180)
    elif sys.argv[1]=="-m" and len(sys.argv)==3:
        ip=sys.argv[2]
        root=CiscoElement("Unknown","Unknown","Unknown",ip)
        elems[ip]=root
        toVisit.append(ip)
        visit()
        if(len(elems)==1):
            elems={}
            root=ExtremeElement("Unknown","Unknown","Unknown",ip)
            elems[ip]=root
            toVisit.append(ip)
            visit()
        
    else:
        print("usage: naspy.py -a [timeout] for automatic sniff of cdp packet (180s default)\ntestSSH.py -m ip for manual search")
else:
    print("usage: nas.py -a [timeout] for automatic sniff of cdp packet (180s default)\ntestSSH.py -m ip for manual search")

