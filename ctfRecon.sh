#!/bin/bash

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Este script debe ejecutarse como root." 
        exit 1
    fi
}

print_help() {
    echo -e "\nEste archivo debe ser ejecutado como root"
    echo -e "\nEl primer parámetro debe ser el nombre del CTF"
    echo -e "\nEl segundo parámetro debe ser la IP de la máquina víctima"
    echo -e "\nEjemplo de uso: ./script.sh nombre_ctf 192.168.1.100"
}

create_directories() {
    mkdir "$1" && cd "$1"
    mkdir recon scan exploits doc enum
}

reconnaissance() {
    echo -e "\n[+] FASE DE RECONOCIMIENTO..."
    osSys
    dnsLookup
}

osSys() {
    echo -e "\nReconocimiento de SO objetivo"
    ping_output=$(ping -c 1 "$targetIP")
    echo "$ping_output" > recon/basicRecon
    ttl_line=$(echo "$ping_output" | grep "ttl=")
    ttl=$(echo "$ttl_line" | awk -F "ttl=" '{print $2}' | awk '{print $1}')

    if [ -n "$ttl" ]; then
        if [ "$ttl" -eq 64 ]; then
            echo -e "\nProbablemente estás haciendo ping a un sistema Linux o macOS."
        elif [ "$ttl" -eq 128 ]; then
            echo -e "\nProbablemente estás haciendo ping a un sistema Windows."
        else
            echo -e "\nNo se puede determinar con certeza el sistema operativo basado en el TTL."
        fi
    else
        echo -e "\nNo se encontró el valor TTL en la salida de ping."
    fi
}

dnsLookup() {
    echo -e "\nRealizando consulta DNS..."
    output=$(dnslookup "$targetIP")
    echo "$output" >> recon/basicRecon
}

scanning_and_enumeration() {
    echo -e "\n[+] FASE DE ESCANEO Y ENUMERACIÓN..."
    scanPorts
    enumPorts
    echo -e "\nSe ha terminado el reconocimiento. ¡Buena suerte para encontrar vulnerabilidades!"
}

scanPorts() {
    echo -e "\nRealizando escaneo de puertos..."
    sudo nmap -sS -n -Pn -min-rate 5000 -p- --open -oG scan/portscan "$targetIP"
    openPorts=$(grep -oP '\d+(?=/open/tcp)' scan/portscan | tr '\n' ',' | sed 's/,$//')
    sudo nmap -sV -sC -oN scan/versionPorts -p T:"$openPorts" "$targetIP"
}

enumPorts() {
    cd enum

    if [[ $openPorts == *'80'* ]]; then
        echo -e "\n   >> HTTP"
        whatweb "http://$targetIP" > httpEnum
        ffuf -c -w /usr/share/wordlists/dirb/big.txt -o httpEnum -u "http://$targetIP/FUZZ"
    elif [[ $openPorts == *'443'* ]]; then
        echo -e "\n   >> HTTPS"
        whatweb "https://$targetIP" > httpsEnum
        ffuf -c -w /usr/share/wordlists/dirb/big.txt -o httpsEnum -u "https://$targetIP/FUZZ"
    elif [[ $openPorts == *'21'* ]]; then
        echo -e "\n   >> FTP"
        nmap -n -Pn -oN ftpScript --script ftp-* -p 21 "$targetIP"
    elif [[ $openPorts == *'22'* ]]; then
        echo -e "\n   >> SSH"
        nmap -n -Pn -oN sshScript --script ssh-* -p 22 "$targetIP"
    elif [[ $openPorts == *'23'* ]]; then
        echo -e "\n   >> TelNet"
        nmap -n -Pn -oN telnetScript --script "*telnet* and safe" -p 23 "$targetIP"
    elif [[ $openPorts == *'25'* || $openPorts == *'465'* || $openPorts == *'587'* ]]; then
        echo -e "\n   >> SMTP"
        nmap -p25,465,587 -oN smtpScript --script smtp-* "$targetIP"
    elif [[ $openPorts == *'53'* ]]; then
        echo -e "\n   >> DNS"
        nmap -n -oN dnsScript --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" "$targetIP"
    elif [[ $openPorts == *'137'* || $openPorts == *'138'* || $openPorts == *'139'* ]]; then
        echo -e "\n   >> NetBios"
        nmblookup -A "$targetIP"
        nbtscan "$targetIP"/30
        sudo nmap -sU -sV -T4 -oN netbiosScript --script nbstat.nse -p137 -Pn -n "$targetIP"
    fi

    cd ..
}

# Verificar los parámetros
if [[ $1 == 'help' && -z $2 ]]; then
    print_help
elif [[ -n $1 && -n $2 ]]; then
    check_root
    ctfName=$1
    targetIP=$2
    create_directories "$ctfName"
    reconnaissance
    scanning_and_enumeration
else
    echo -e "\nAlgo no ha salido bien"
    echo -e "\nEl primer parámetro debe ser el nombre del CTF"
    echo -e "\nEl segundo parámetro debe ser la IP de la máquina víctima"
fi
