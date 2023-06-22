#!/bin/bash

ip=$1

dir() {
    mkdir nmap && mkdir exploits && mkdir doc && mkdir enum
    scanyenum
}

scanyenum() {
    cd nmap
    sudo nmap -sS -n -Pn -min-rate 5000 -p- --open -oX portscan "$ip"
    openPorts=$(grep -oP '\d+(?=/open/tcp)' portscan | tr '\n' ',' | sed 's/,$//')
    sudo nmap -sV -sC -oN versionPorts -p "$openPorts" "$ip"

    cd enum
    if [[ $openPorts == *'80'* ]]; then
        ffuf -c -w /usr/share/wordlists/dirb/big.txt -o httpEnum -u "http://$ip/FUZZ"
        whatweb "http://$ip" >> httpEnum
    elif [[ $openPorts == *'443'* ]]; then
        ffuf -c -w /usr/share/wordlists/dirb/big.txt -o httpsEnum -u "https://$ip/FUZZ"
        whatweb "http://$ip" >> httpsEnum
    fi

    cd ..
    echo -e "\nFIN!"
}

if [[ $1 == 'help' ]]; then
    echo -e "\nEste archivo debe ser ejecutado como root"
    echo -e "\nEl primer parámetro debe ser el nombre del CTF"
    echo -e "\nEl segundo parámetro debe ser el IP de la maquina victima"
elif [[ $1 ]]; then
    dir
else
    echo -e "\nAlgo no ha salido bien"
fi
