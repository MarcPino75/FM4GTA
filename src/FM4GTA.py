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

def blockPortsRangeBuilder(allowPortsIn):

    allowPorts = list(set(allowPortsIn))

    allowPorts.sort()

    blockedRanges = []

    for idx, port in enumerate(allowPorts):
        if idx == 0:
            blockedRanges.append("0-" + str(port - 1))
        else:
            blockedRanges.append(str(allowPorts[idx-1] + 1) + "-" + str(port - 1))
    
    blockedRanges.append(str(allowPorts[allowPorts.__len__() - 1] + 1) + "-65535")

    return ','.join(blockedRanges)

def blockIPRangeBuilder(allowIPsIn):
    
    allowIPs = list(set(allowIPsIn))

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
    
def implementFRules(ips, udpPorts, tcpPorts, fileloc):
    ruleInUDP = FRule(name="FM4GTA", \
    direction="in", \
    filepath=fileloc, \
    action="block", \
    protocol="udp", \
    reIP=blockIPRangeBuilder(ips), \
    rePO="any", \
    loIP="any", \
    loPO=blockPortsRangeBuilder(udpPorts))

    ruleOutUDP = FRule(name="FM4GTA", \
    direction="out", \
    filepath=fileloc, \
    action="block", \
    protocol="udp", \
    reIP=blockIPRangeBuilder(ips), \
    rePO=blockPortsRangeBuilder(udpPorts), \
    loIP="any", \
    loPO="any")
    
    ruleInTCP = FRule(name="FM4GTA", \
    direction="in", \
    filepath=fileloc, \
    action="block", \
    protocol="tcp", \
    reIP=blockIPRangeBuilder(ips), \
    rePO="any", \
    loIP="any", \
    loPO=blockPortsRangeBuilder(tcpPorts))

    ruleOutTCP = FRule(name="FM4GTA", \
    direction="out", \
    filepath=fileloc, \
    action="block", \
    protocol="tcp", \
    reIP=blockIPRangeBuilder(ips), \
    rePO=blockPortsRangeBuilder(tcpPorts), \
    loIP="any", \
    loPO="any")

    print(ruleInUDP.getRuleString())
    sendCommand(ruleInUDP.getRuleString())
    print(ruleOutUDP.getRuleString())
    sendCommand(ruleOutUDP.getRuleString())
    print(ruleInTCP.getRuleString())
    sendCommand(ruleInTCP.getRuleString())
    print(ruleOutTCP.getRuleString())
    sendCommand(ruleOutTCP.getRuleString())

def clearFR():
    sendCommand("netsh advfirewall firewall delete rule name=FM4GTA")

def setFileLoc():
    root = tk.Tk()
    root.withdraw()
    fp = filedialog.askopenfilename()
    return fp.replace('/', '\\')

lesIPs = []
tIP = []
lesPortsUDP = []
tports = []
lesPortsTCP = []
tportsTCP = []
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

with open('clientPath.txt', 'r') as f:
    cPath = f.readline()

for port in tports[0]:
    lesPortsUDP.append(int(port))
for port in tports[1]:
    lesPortsTCP.append(int(port))

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
    print(lesPortsUDP)
    print(lesPortsTCP)
    print(cPath)

    uInput = input('\nSelect mode :\n1. Implement FRs\n2. Delete FRs\n3. Set file location\n\n')

    if uInput == "1":
        print("\nImplement FR chosen\n")
        implementFRules(lesIPs, lesPortsUDP, lesPortsTCP, cPath)
    elif uInput == "2":
        print("\nDelete FR chosen\n")
        clearFR()
    elif uInput == "3":
        filePath = setFileLoc()
        with open("clientPath.txt", "w") as f :
            f.writelines([filePath])
        
    input("Appuyez sur entrée pour continuer")
else:
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)


