#!/usr/bin/python3
# Librerias para ejecucion de comandos
import sys
import subprocess
from subprocess import STDOUT
import os

name = str(sys.argv[1])
ip = str(sys.argv[2])

def dir():
    os.system('mkdir '+name+' && cd '+name)
    os.system('mkdir nmap && mkdir exploits && mkdir doc && mkdir enum')

def scanyenum():
    os.system('cd nmap')
    os.system('sudo nmap -sS -n -Pn -min-rate 5000 -p- --open -oX portscan'+ip)
    salida = subprocess.check_output("grep -oP '\d+(?=/open/tcp)' portscan | tr '\n' ',' | sed 's/,$//'", shell=True, text=True)
    openPorts = salida.strip()
    os.system('sudo nmap -sV -sC -oN versionPorts -p '+openPorts+' '+ip)
    os.system('cd ..')

    os.system('cd enum')
    if '80' in openPorts.split(','):
        os.system('ffuf -c -w /usr/share/wordlists/dirb/big.txt -o httpEnum -u http://'+ip+'/FUZZ')
        os.system('whatweb http://'+ip+ '>> httpEnum')
    elif '443' in openPorts.split(','):
        os.system('ffuf -c -w /usr/share/wordlists/dirb/big.txt -o httpsEnum -u https://'+ip+'/FUZZ')
        os.system('whatweb http://'+ip+ '>> httpsEnum')

    os.system('cd ..')

if sys.argv[1]=='help':
    print("\nEste archivo debe ser ejecutado como root")
    print("\nEl primer parámetro debe ser el nombre del CTF")
    print("\nEl segundo parámetro debe ser el IP de la maquina victima")
elif sys.argv[1] and sys.argv[2]:
    dir()
else:
    print("\nAlgo no ha salido bien")