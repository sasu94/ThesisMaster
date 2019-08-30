import paramiko
import re
import json
import pyshark
import sys
import json
import os
if os.geteuid() != 0:
    print('You need to run as root!')
    exit()
from LogSender import *
import difflib
from cryptography.fernet import Fernet

toVisit=[]
visited=[]
elems={}
elemsByMac={}

class EntryNotFoundException(Exception):
    pass

class ElementException(Exception):
    pass

class Element:
    """
    An abstract class modeling an element in the topology
    ----------
    type : str
        the typology of element
    name : str
        the name of the element
    platform : str
        the platform of the element
    ip : str
        the IP address of the element
    mac : str
        the MAC address of the element
    links : list(Link)
        the list of links of the element
    Methods
    -------
    connectionSSH()
        Perform the connection to SSH to the element
    addLink()
        Adds a link to the list of links
    addMac()
        Adds the MAC address to the element
    """
    
    
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
        """
        Adds the MAC address to the element
        
        Parameters
        ----------
        mac:str
            the MAC address to add

        """
        self.mac=mac
    def addLink(self,link):
        """
        Adds a link to the list of links
        
        Parameters
        ----------
        link:Link
            the link to add

        """
        self.links.append(link)
    def toJSON(self):
        return json.dumps(self,default=lambda o:o.__dict__)
    def connectionSSH(self,db):
        """
        Perform the connection to SSH to the element
        
        Parameters
        ----------
        db:dict
            the dictionary of credentials

        Returns
        -------
        int
            returns the count of elements found

        """
        print("\ntrying to connect to: "+self.ip+"\n\nunable to connect to SSH")
        return 0
    
    def parseCDP(self, text):
        """
        Parses an entry for CDP table
        
        Parameters
        ----------
        text:str
            the text to parse
        """
        pass
    def parseLLDP(self,text):
        """
        Parses an entry of the LLDP table
        
        Parameters
        ----------
        text:str
            the text to parse
        """
        pass
    def parseArp(self,text):
        """
        Parses an ARP Table
        
        Parameters
        ----------
        text:str
            the text to parse
        """
        pass
    def parseMacTable(self, text):
        """
        Parses a mac Table
        
        Parameters
        ----------
        text:str
            the text to parse
        """
        pass
    
    
class CiscoElement(Element):
    def connectionSSH(self,db):
        """
        Perform the connection to SSH to the element
        
        Parameters
        ----------
        db:dict
            the dictionary of credentials

        Returns
        -------
        int
            returns the count of elements found

        """
        list=[]
        ip=self.ip
        count=0
        print("\ntrying to connect to: "+self.ip+"\n")
        try:
            client=paramiko.SSHClient()
            if ip not in db:
                raise EntryNotFoundException
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=ip,username=db[ip]['user'],password=db[ip]['pass'])

            sh=client.invoke_shell()
            sh.send("en\n")
            resp=''
            while not re.search('.*Password.*',resp):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')
                    if 'Incomplete' in resp:
                        raise ElementException
            
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
            return count
        
    def parseCDP(self, text):
        """
        Parses an entry for CDP table
        
        Parameters
        ----------
        text:str
            the text to parse

        Returns
        -------
        bool
            returns true if the element is added, false otherwise

        """
        added=False  
        try:       
            s=text.split("\n")
            
            name=ip=fr=to=plat=capa='Unknown'
            
            for t in s:
                if re.search('Device ID: (.*)',t):
                    name=re.search('Device ID: (.*)',t).group(1).strip()
                elif re.search('.*IP address: (.*)',t):
                    ip=re.search('.*IP address: (.*)',t).group(1).strip()
                elif re.search('.*Interface:.*',t):
                    ports=t.split(',')
                    fr=re.search('.*: (.*)',ports[0]).group(1).strip()        
                    to=re.search('.*: (.*)',ports[1]).group(1).strip()
                elif re.search('.*Platform:.*',t):
                    info=t.split(',')
                    plat=re.search('.*Platform: (.*)',info[0]).group(1).strip()        
                    capa=re.search('.*Capabilities: (.*)',info[1]).group(1).strip()
            
            
            if 'EXOS' in plat  or 'Extreme' in plat:
                to='Port '+to
            
            if ip in elems and isinstance(elems[ip],(ExtremeElement,CiscoElement)):
                element=elems[ip]
                if element.type=='Unknown':
                    element.type=capa
                if element.platform=='Unknown':
                    element.platform=platform
                if element.name=='Unknown':
                    element.name=name       
                
                
            else:
                if 'Cisco' in plat:
                    element=CiscoElement(capa,name,plat,ip)
                elif 'EXOS' in plat or 'Extreme' in plat:
                    element=ExtremeElement(capa,name,plat,ip)
                else:
                    element=Element(capa,name,plat,ip)
                elems[ip]=element
                
            l=Link(fr,to,element)
            
            if l not in self.links:
                added=True
                self.addLink(l)
            
            if(ip not in visited and ip not in toVisit):
                toVisit.append(ip)
        except:
            print('found new element but not enough information to be added\n')
        finally:
            return added
            
    def parseLLDP(self,text):
        """
        Parses an entry of the LLDP table
        
        Parameters
        ----------
        text:str
            the text to parse

        Returns
        -------
        bool
            returns true if the element is added, false otherwise

        """
        
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

            
            if ip in elems and isinstance(elems[ip],(ExtremeElement,CiscoElement)):
                element=elems[ip]
                if element.type=='Unknown':
                    element.type=capa
                if element.platform=='Unknown':
                    element.platform=plat
                if element.name=='Unknown':
                    element.name=name         
            else:
                if 'Cisco' in plat:
                    element=CiscoElement(capa,name,plat,ip)
                elif 'Extreme' in plat or 'EXOS' in plat:
                    element=ExtremeElement(capa,name,plat,ip)
                else:
                    element=Element(capa,name,plat,ip)
                elems[ip]=element
                
            l=Link(fr,to,element)
            
            if l not in self.links:
                added=True
                self.addLink(l)
            
            if(ip not in visited and ip not in toVisit):
                toVisit.append(ip)
        except:
            print('found new element but not enough information to be added\n')
        finally:
            return added
            
            
    def parseArp(self,text):
        """
        Parses an ARP Table
        
        Parameters
        ----------
        text:str
            the text to parse
        """

        text=re.compile('\s\s+').split(text)
        ip=text[1]
        mac=text[3]
        
        element=None
        
        if ip in elems:
            element=elems[ip]
        else:
            element=Element("Unknown","Unknown","Unknown",ip)
            elems[ip]=element
            
        element.addMac(mac)
        
        elemsByMac[mac]=element

    def parseMacTable(self, text):
        """
        Parses a mac Table
        
        Parameters
        ----------
        text:str
            the text to parse

        Returns
        -------
        int
            returns the count of elements found

        """
        
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
                    toVisit.append(element.ip)
        
        return added
        

class ExtremeElement(Element):
    def connectionSSH(self,db):
        """
        Perform the connection to SSH to the element
        
        Parameters
        ----------
        db:dict
            the dictionary of credentials

        Returns
        -------
        int
            returns the count of elements found

        """
        list=[]
        ip=self.ip
        count=0
        print("\ntrying to connect to: "+self.ip+"\n")
        try:
            client=paramiko.SSHClient()
            if ip not in db:
                raise EntryNotFoundException
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=ip,username=db[ip]['user'],password=db[ip]['pass'])
            
            sh=client.invoke_shell()
            sh.send("disable clipaging\n")
            resp=''
            while not re.search('.*EXOS-VM.2.*#',resp):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')
                    if 'Invalid' in resp:
                        raise ElementException
            
            
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
            
            for text in cdp:
                if self.parseCDP(text):
                    count+=1
            
            buff=''
            sh.send("show iparp\n")
            sh.send("\n");
            
            while not re.search('.*# \r\n.*#.*',buff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')    
                    buff+=resp
            
            arp=buff.split("\n")
            arp=arp[3:(len(arp)-18)]
            for text in arp:
                self.parseArp(text)
            
            buff=''
            sh.send("show fdb\n")
            sh.send("\n");
            
            while not re.search('.*# \r\n.*#.*',buff):
                if sh.recv_ready():
                    resp = sh.recv(9999).decode('ascii')    
                    buff+=resp

            
            sh.send("exit\r\n")
            
            mac_table=buff.split("\n")
            mac_table=mac_table[4:(len(mac_table)-12)]
            
            count+=self.parseMacTable(mac_table)
            
            print('links found for '+self.ip+': '+str(count))
           
        except:
            print('unable to connect to SSH')
        finally:
            client.close()
            return count
        
    def parseCDP(self,text):
        """
        Parses an entry for CDP table
        
        Parameters
        ----------
        text:str
            the text to parse

        Returns
        -------
        bool
            returns true if the element is added, false otherwise

        """
        added=False  
        try:       
            s=text.split("\n")
            
            name=ip=fr=to=plat=capa='Unknown'
            
            for t in s:
                if re.search('Device ID\s+: (.*)',t):
                    name=re.search('Device ID\s+: (.*)',t).group(1).strip()
                elif re.search('.*IP Addresses.*',t):
                    ip=re.search('\t(.*)',s[s.index(t)+1]).group(1).strip()
                elif re.search('.*Port ID.*',t):
                    to=re.search('.*Port ID.*: (.*)',t).group(1).strip()
                elif re.search('.*Interface.*',t):
                    fr='Port '+re.search('.*Interface.*: (.*)',t).group(1).strip()
                elif re.search('.*Platform.*:.*',t):
                    plat=re.search('.*Platform.*: (.*)',t).group(1).strip()        
                elif re.search('.*Capabilities.*:.*',t):
                    capa=re.search('.*Capabilities.*: (.*)',info[1]).group(1).strip()
            
            
            if ip in elems:
                element=elems[ip]
                if element.type=='Unknown':
                    element.type=capa
                if element.platform=='Unknown':
                    element.platform=platform
                if element.name=='Unknown':
                    element.name=name       
                
                
            else:
                if 'Cisco' in plat:
                    element=CiscoElement(capa,name,plat,ip)
                elif 'Extreme' in plat:
                    element=ExtremeElement(capa,name,plat,ip)
                else:
                    element=Element(capa,name,plat,ip)
                elems[ip]=element
                
            l=Link(fr,to,element)
            
            if l not in self.links:
                added=True
                self.addLink(l)
            
            if(ip not in visited and ip not in toVisit):
                toVisit.append(ip)
        except:
            print('found new element but not enough information to be added\n')
        finally:
            return added
            
    def parseLLDP(self, text):
        """
        Parses an entry of the LLDP table
        
        Parameters
        ----------
        text:str
            the text to parse

        Returns
        -------
        bool
            returns true if the element is added, false otherwise

        """
        
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
            
            if ip in elems:
                element=elems[ip]
                if element.type=='Unknown':
                    element.type=capa
                if element.platform=='Unknown':
                    element.platform=plat
                if element.name=='Unknown':
                    element.name=name         
            else:
                if 'Cisco' in plat:
                    element=CiscoElement(capa,name,plat,ip)
                elif 'Extreme' in plat or 'EXOS' in plat:
                    element=ExtremeElement(capa,name,plat,ip)
                else:
                    element=Element(capa,name,plat,ip)
                elems[ip]=element
                
            l=Link(fr,to,element)
            
            if l not in self.links:
                added=True
                self.addLink(l)
            
            if(ip not in visited and ip not in toVisit):
                toVisit.append(ip)
        except:
            print('found new element but not enough information to be added')
        finally:
            return added
            
            
    def parseArp(self,text):
        """
        Parses an ARP Table
        
        Parameters
        ----------
        text:str
            the text to parse
        """
        text=re.compile('\s\s+').split(text)
        ip=text[1]
        mac=text[2]
        
        element=None
        
        if ip in elems:
            element=elems[ip]
        else:
            element=Element("Unknown","Unknown","Unknown",ip)
            elems[ip]=element
            
        if(element.mac==''):
            element.addMac(mac)
        
        if mac not in elemsByMac:
            elemsByMac[mac]=element
    
     
    def parseMacTable(self, text):
        """
        Parses a mac Table
        
        Parameters
        ----------
        text:str
            the text to parse

        Returns
        -------
        int
            returns the count of elements found

        """
    
        added=0
        single_occurrences=[]
        
        for i in range(len(text)):
            r1=re.compile('\s\s+').split(text[i])
            found=False
            for j in range(len(text)):
                r2=re.compile('\s\s+').split(text[j])
                if(r1[3]==r2[3] and r1[0]!=r2[0]):
                    found=True
            if not found:
                single_occurrences.append(r1)
                
        for entry in single_occurrences:
            if entry[0] in elemsByMac:
                element=elemsByMac[entry[3]]
                l=Link('Port '+entry[3].strip(),'Unknown',element)
                
                if l not in curr.links:
                    added+=1
                    curr.addLink(l)
                
                if(element.ip not in visited and element.ip not in toVisit):
                    toVisit.append(element.ip)
        
        return added



class Link:
    """
    A class modeling a link between two elements
    ----------
    port1 : str
        the port of the element owning this object
    port2 : str
        the port of the element connected
    element : Element
        the element with which is connected the one possessing this object
    """
    
    def __init__(self,port1,port2,element):
        self.port1=port1
        self.port2=port2
        self.element=element
        
    def __eq__(self, other):
        return self.element == other.element

    def __hash__(self):
        return hash(self.element.ip)
      
def decryptdb():
    """
    Takes the file with the database of entries and decrypts it

    Returns
    -------
    dict
        returns a dictionary consisting in the database

    """ 
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
    """
    A BFS that visits the topology
    """

    db=decryptdb()
    found=False
    while(toVisit):
        ip=toVisit.pop(0)
        element=elems[ip]
        if element.connectionSSH(db)>0:
            found=True
        visited.append(ip)
    
    if found:
        constructJSON()
        
        
def constructJSON():
    """
    Constructs the json outputs and sends an email with the results
    """
    
    
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
    with open('Webpage/data.json') as f2:
        oldFile=f2.read()

    newElements=[]
    for line in list(difflib.unified_diff(oldFile.split('\n'), nF, fromfile='oldFile', tofile='newFile',lineterm="\n"))[2:]:
        end=0
        if line[len(line)-1]==',':
            end=len(line)-2
        else:
            end=len(line)-1
    
        if '{' in line:
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
        
    logSender=LogSender()
    print()
    logSender.send('salvatore.mon@gmail.com','Scan finished!','Results',["\n".join(nF),diffFile],['json','json'],['data','diff'])
    
    


def sniff(timeout):
    """
    Tries to sniff a packet CDP or LLDP and then starts a visit
    
    Parameters
    ----------
    timeout : int
        the maximum time in seconds to wait to receive a packet

    """
    try:
        print("start sniffing\n")
        cap=pyshark.LiveCapture('eth0',display_filter='cdp or lldp')
        cap.sniff(packet_count=1,timeout=timeout)
        if cap:
            pack=cap[0]
            root=None
            if 'cdp' in pack:
                id=pack.cdp.deviceid.strip()
                ip=pack.cdp.nrgyz_ip_address.strip()
                capa=pack.cdp.capabilities.strip()
                platform=pack.cdp.platform.strip()               
            else:
                id=pack.lldp.tlv_system_name.strip()
                ip=pack.lldp.mgn_addr_ip4.strip()
                capa=pack.lldp.tlv_system_cap.strip()
                platform=pack.lldp.tlv_system_desc.strip()           
                
            if 'Cisco' in platform:
                root=CiscoElement(capa,id,platform,ip)
            elif 'EXOS' in platform or 'Extreme' in platform:
                root=ExtremeElement(capa,id,platform,ip)
            else:
                root=Element(capa,id,platform,ip)    
                
            elems[ip]=root
            toVisit.append(ip)
            visit()
        else:
            print("time expired")
    finally:
        cap.eventloop.close()
        
        
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
            print('Probably not a Cisco device, trying with an Extreme')
            elems={}
            root=ExtremeElement("Unknown","Unknown","Unknown",ip)
            elems[ip]=root
            toVisit.append(ip)
            visit()
    else:
        print("usage: naspy.py -a [timeout] for automatic sniff of cdp packet (180s default)\nnaspy.py -m ip for manual search")
else:
    print("usage: naspy.py -a [timeout] for automatic sniff of cdp packet (180s default)\nnaspy.py -m ip for manual search")

