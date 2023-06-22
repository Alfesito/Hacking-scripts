#!/bin/bash

name=$1
ip=$2

dir() {
    mkdir "$name" && cd "$name"
    mkdir scan && mkdir exploits && mkdir doc && mkdir enum
    scanyenum
}

scanyenum() {
    cd scan
    sudo nmap -sS -n -Pn -min-rate 5000 -p- --open -oG portscan "$ip"
    openPorts=$(grep -oP '\d+(?=/open/tcp)' portscan | tr '\n' ',' | sed 's/,$//')
    sudo nmap -sV -sC -oN versionPorts -p"$openPorts" "$ip"

    cd ../enum
    if [[ $openPorts == *'80'* ]]; then
        echo -e "\HTTP"
        whatweb "http://$ip"
        ffuf -c -w /usr/share/wordlists/dirb/big.txt -o httpEnum -u "http://$ip/FUZZ"
        whatweb "http://$ip" >> httpEnum
        continue
    elif [[ $openPorts == *'443'* ]]; then
        echo -e "\HTTPS"
        whatweb "https://$ip"
        ffuf -c -w /usr/share/wordlists/dirb/big.txt -o httpsEnum -u "https://$ip/FUZZ"
        whatweb "https://$ip" >> httpsEnum
        continue
    elif [[ $openPorts == *'21'* ]]; then
        echo -e "\FTP"
        nmap  -n -Pn -oN ftpScript --script ftp-* -p 21 "$ip"
        continue
    elif [[ $openPorts == *'22'* ]]; then
        echo -e "\SSH"
        nmap  -n -Pn -oN sshScript --script ssh-* -p 22 "$ip"
        continue
    elif [[ $openPorts == *'23'* ]]; then
        echo -e "\TelNet!"
        nmap -n -Pn -oN telnetScript --script "*telnet* and safe" -p 23 "$ip"
        continue
    elif [[ $openPorts == *'25'* || $openPorts == *'465'* || $openPorts == *'587'* ]]; then
        echo -e "\SMTP"
        nmap -p25,465,587 -oN smtpScript --script smtp-* "$ip"
        continue
    elif [[ $openPorts == *'53'* ]]; then
        echo -e "\DNS"
        nmap -n -oN dnsScript --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" "$ip"
        continue
    elif [[ $openPorts == *'137'* || $openPorts == *'138'* || $openPorts == *'139'* ]]; then
        echo -e "\NetBios"
        nmblookup -A "$ip"
        nbtscan "$ip"/30
        sudo nmap -sU -sV -T4 -oN netbiosScript --script nbstat.nse -p137 -Pn -n "$ip"
        continue
    fi

    cd ..
    echo -e "\nFIN!!"
}

if [[ $1 == 'help' ]]; then
    echo -e "\nEste archivo debe ser ejecutado como root"
    echo -e "\nEl primer parámetro debe ser el nombre del CTF"
    echo -e "\nEl segundo parámetro debe ser el IP de la maquina victima"
elif [[ $1 && $2 ]]; then
    dir
else
    echo -e "\nAlgo no ha salido bien"
fi
