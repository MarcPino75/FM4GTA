from requests import get
import tkinter as tk
from tkinter import filedialog
import subprocess
import os
import ctypes
import sys
import ipaddress as ip

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
    loIP, reIP, loPO, rePO):
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

    return ', '.join(blockedRanges)


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

    
r1 = FRule(name="RegleTest", \
direction="in", \
filepath="C:\Program Files\Rockstar Games\Grand Theft Auto V\GTA5.exe", \
action="block", \
protocol="udp", \
loIP="192.168.1.46", \
reIP="192.168.1.46", \
loPO="5454", \
rePO="5454")

#print(r1.getRuleString())
#sendCommand(r1.getRuleString())

print(blockPortsRangeBuilder([5353, 27013, 15758]))

