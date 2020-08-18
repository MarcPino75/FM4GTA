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
        
    subprocess.call(commande)
    
    #def is_admin():
    #    try:
    #        return ctypes.windll.shell32.IsUserAnAdmin()
    #    except:
    #        return False

    #if is_admin():
    #    subprocess.call(commande)
    #else:
        # Re-run the program with admin rights
    #    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

def implementFRules(ips, ports, fileloc):
    ruleIn = FRule(name="FM4GTA", \
    direction="in", \
    filepath=fileloc, \
    action="block", \
    protocol="udp", \
    reIP=blockIPRangeBuilder(ips), \
    rePO=blockPortsRangeBuilder(ports), \
    loIP="any", \
    loPO=blockPortsRangeBuilder(ports))

    ruleOut = FRule(name="FM4GTA", \
    direction="out", \
    filepath=fileloc, \
    action="block", \
    protocol="udp", \
    reIP=blockIPRangeBuilder(ips), \
    rePO=blockPortsRangeBuilder(ports), \
    loIP="any", \
    loPO=blockPortsRangeBuilder(ports))
    
    print(ruleIn.getRuleString())
    sendCommand(ruleIn.getRuleString())
    print(ruleOut.getRuleString())
    sendCommand(ruleOut.getRuleString())

def clearFR():
    sendCommand("netsh advfirewall firewall delete rule name=FM4GTA")

#def setFileLoc():
#    Tk().withdraw() # we don't want a full GUI, so keep the root window from appearing
#    filename = askopenfilename() # show an "Open" dialog box and return the path to the selected file
#    file = open("clientPath.txt", "w") 
#    file.write(filename) 
 #   file.close() 

lesIPs = []
tIP = []
lesPorts = []
tports = []
#loc = ""

with open('friendsFM4GTA.csv', newline='') as friendsfile:
    csvRead = csv.reader(friendsfile, delimiter=',')
    for row in csvRead:
        tIP.append(row[1])
friendsfile.close()

with open('portsFM4GTA.csv', newline='') as portsfile:
    csvRead = csv.reader(portsfile, delimiter=',')
    for row in csvRead:
        tports.append(row)
portsfile.close()

#with open('clientPath.txt', 'r') as f:
#    print(f.readline)

for port in tports[0]:
    lesPorts.append(int(port))

for unIP in tIP:
    lesIPs.append(ip.ip_address(unIP))

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if is_admin():
    
    print("\nVotre IP externe est : " + getIP())
    
    print(lesIPs)
    print(lesPorts)

    uInput = input('\nSelect mode :\n1. Implement FRs\n2. Delete FRs\n3. Set file location\n\n')

    if uInput == "1":
        print("\nImplement FR chosen\n")
        implementFRules(lesIPs, lesPorts, "C:\Program Files\Rockstar Games\Grand Theft Auto V\GTA5.exe")
    elif uInput == "2":
        print("\nDelete FR chosen\n")
        clearFR()
    #elif uInput == "3":
    #    setFileLoc()
    input("Appuyez sur entrée pour continuer")
else:
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)


