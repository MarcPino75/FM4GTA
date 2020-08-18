from requests import get
import tkinter as tk
from tkinter import filedialog
import subprocess
import os
import ctypes
import sys
import ipaddress as ip
import csv

class FRule:
    
    name = ""
    direc = ""
    act = ""
    progFP = ""
    serv = "any"
    desc = "Automated rule for GTAO"
    endis = "yes"
    profile = "any"
    localip = ""
    remoteip = ""
    localport = ""
    remoteport = ""
    prot = ""
    interf = "any"
    
    def __init__(self, name, direction, filepath, action, protocol,
    reIP, rePO, loIP, loPO):
        self.name = name
        self.direc = direction
        self.act = action
        self.progFP = filepath
        self.localip = loIP
        self.remoteip = reIP
        self.localport = loPO
        self.remoteport = rePO
        self.prot = protocol

    def getRuleString(self):
        return "netsh advfirewall firewall add rule " + \
        "name=" + '"' + self.name + '"' + " " + \
        "dir=" + '"' + self.direc + '"' + " " \
        "act=" + '"' + self.act + '"' + " " \
        "program=" + '"' + self.progFP + '"' + " " \
        "localip=" + '"' + self.localip + '"' + " " \
        "remoteip=" + '"' + self.remoteip + '"' + " " \
        "localport=" + '"' + self.localport + '"' + " " \
        "remoteport=" + '"' + self.remoteport + '"' + " " \
        "protocol=" + '"' + self.prot + '"' + " " \
        "enable=" + '"' + self.endis + '"' + " " \
        "description=" + '"' + self.desc + '"' + " " \
        "service=" + '"' + self.serv + '"' + " " \
        "interface=" + '"' + self.interf + '"' 
        
#"=" + '"' + self. + '"' + " " \

def blockPortsRangeBuilder(allowPorts):

    allowPorts.sort()

    blockedRanges = []

    for idx, port in enumerate(allowPorts):
        if idx == 0:
            blockedRanges.append("0-" + str(port - 1))
        else:
            blockedRanges.append(str(allowPorts[idx-1] + 1) + "-" + str(port - 1))
    
    blockedRanges.append(str(allowPorts[allowPorts.__len__() - 1] + 1) + "-65535")

    return ','.join(blockedRanges)

def blockIPRangeBuilder(allowIPs):
    
    allowIPs.sort()
    
    blockedRanges = []

    for idx, uneIP in enumerate(allowIPs):
        if idx == 0:
            blockedRanges.append("0.0.0.0-" + str(uneIP - 1))
        else:
            blockedRanges.append(str(allowIPs[idx-1] + 1) + "-" + str(uneIP - 1))
    
    blockedRanges.append(str(allowIPs[allowIPs.__len__() - 1] + 1) + "-255.255.255.255")

    return ','.join(blockedRanges)
    

def str2IP(strIPs):
    
    ip2return = []
    
    for ips in strIPs:
        ip2return.append(ip.ip_address(ips))       

    return ip2return


def getIP():
    return get('https://api.ipify.org').text

def sendCommand(commande):
        
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    if is_admin():
        subprocess.call(commande)
    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

def implementFRules(ips, ports):
    ruleIn = FRule(name="FM4GTA", \
    direction="in", \
    filepath="C:\Program Files\Rockstar Games\Grand Theft Auto V\GTA5.exe", \
    action="block", \
    protocol="udp", \
    reIP=blockIPRangeBuilder(ips), \
    rePO=blockPortsRangeBuilder(ports), \
    loIP="any", \
    loPO=blockPortsRangeBuilder(ports))

    ruleOut = FRule(name="FM4GTA", \
    direction="out", \
    filepath="C:\Program Files\Rockstar Games\Grand Theft Auto V\GTA5.exe", \
    action="block", \
    protocol="udp", \
    reIP=blockIPRangeBuilder(ips), \
    rePO=blockPortsRangeBuilder(ports), \
    loIP="any", \
    loPO=blockPortsRangeBuilder(ports)) 

def clearFR():
    sendCommand("netsh advfirewall firewall delete rule name=FM4GTA")

ips = []
ports = []

with open('friendsFM4GTA.csv', newline='') as friendsfile:
    csvRead = csv.reader(friendsfile, delimiter=',')
    for row in csvRead:
        ips.append(row[1])
friendsfile.close()

with open('portsFM4GTA.csv', newline='') as portsfile:
    csvRead = csv.reader(portsfile, delimiter=',')
    for row in csvRead:
        ports.append(row)



#headerF = ["users","ips","ports"]
#headerP = ["ports2Allow"]

#ips = [ip.ip_address('184.144.156.43')]
#ports = [5353, 17185, 27036]

#with open("friendsFM4GTA.csv", "w", newline='') as filedata :                          
#    writer = csv.writer(filedata, delimiter=',')
#    writer.writerow(['Marc', '184.144.156.43'])

#with open ("portsFM4GTA.csv", "w", newline='') as filedata:                            
#    writer = csv.writer(filedata, delimiter=',')
#    writer.writerow(ports)


#print(r1.getRuleString())
#sendCommand(r1.getRuleString())
#print(getIP())

#rTest = FRule(name="RegleTest", \
#direction="in", \
#filepath="C:\Program Files\Rockstar Games\Grand Theft Auto V\GTA5.exe", \
#action="block", \
#protocol="udp", \
#reIP=blockIPRangeBuilder(ips), \
#rePO=blockPortsRangeBuilder(ports), \
#loIP="any", \
#loPO=blockPortsRangeBuilder(ports))



