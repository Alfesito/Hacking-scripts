#!/bin/bash

name=$1
ip=$2

dir() {
    mkdir "$name" && cd "$name"
    mkdir recon && mkdir scan && mkdir exploits && mkdir doc && mkdir enum
    if [[ $2 ]]; then
        recon
        scanyenum
}

recon() {
    echo -e "\n[+] FASE DE RECONOCIMIENTO..."
    cd recon
    osSys
    output2=$(dnslookup "$ip")
    echo "$output2" >> basicRecon
    cd ..
}

osSys(){
    echo -e "\n Reconocimiento de SO objetivo"
    ping_output=$(ping -c 1 "$ip")  # Ejecuta el comando ping y almacena la salida en una variable
    echo "$ping_output" > basicRecon
    ttl_line=$(echo "$ping_output" | grep "ttl=")  # Obtiene la línea que contiene el valor TTL
    ttl=$(echo "$ttl_line" | awk -F "ttl=" '{print $2}' | awk '{print $1}')  # Extrae el valor TTL de la línea

    if [ -n "$ttl" ]; then
        if [ "$ttl" -eq 64 ]; then
            echo "\nProbablemente estás haciendo ping a un sistema Linux o macOS."
        elif [ "$ttl" -eq 128 ]; then
            echo "\nProbablemente estás haciendo ping a un sistema Windows."
        else
            echo "\nNo se puede determinar con certeza el sistema operativo basado en el TTL."
        fi
    else
        echo "\nNo se encontró el valor TTL en la salida de ping."
    fi
}

scanyenum() {
    echo -e "\n[+] FASE DE ESCANEO Y ENUMERACIÓN..."
    cd scan
    sudo nmap -sS -n -Pn -min-rate 5000 -p- --open -oG portscan "$ip"
    openPorts=$(grep -oP '\d+(?=/open/tcp)' portscan | tr '\n' ',' | sed 's/,$//')
    sudo nmap -sV -sC -oN versionPorts -p"$openPorts" "$ip"

    cd ../enum
    if [[ $openPorts == *'80'* ]]; then
        echo -e "\n   >> HTTP"
        output1=$(whatweb "http://$ip")
        echo "$output1" > httpEnum
        ffuf -c -w /usr/share/wordlists/dirb/big.txt -o httpEnum -u "http://$ip/FUZZ"
        continue
    elif [[ $openPorts == *'443'* ]]; then
        echo -e "\n   >> HTTPS"
        output2=$(whatweb "https://$ip")
        echo "$output2" > httpsEnum
        ffuf -c -w /usr/share/wordlists/dirb/big.txt -o httpsEnum -u "https://$ip/FUZZ"
        continue
    elif [[ $openPorts == *'21'* ]]; then
        echo -e "\n   >> FTP"
        nmap  -n -Pn -oN ftpScript --script ftp-* -p 21 "$ip"
        continue
    elif [[ $openPorts == *'22'* ]]; then
        echo -e "\n   >> SSH"
        nmap  -n -Pn -oN sshScript --script ssh-* -p 22 "$ip"
        continue
    elif [[ $openPorts == *'23'* ]]; then
        echo -e "\n   >> TelNet"
        nmap -n -Pn -oN telnetScript --script "*telnet* and safe" -p 23 "$ip"
        continue
    elif [[ $openPorts == *'25'* || $openPorts == *'465'* || $openPorts == *'587'* ]]; then
        echo -e "\n   >> SMTP"
        nmap -p25,465,587 -oN smtpScript --script smtp-* "$ip"
        continue
    elif [[ $openPorts == *'53'* ]]; then
        echo -e "\n   >> DNS"
        nmap -n -oN dnsScript --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" "$ip"
        continue
    elif [[ $openPorts == *'137'* || $openPorts == *'138'* || $openPorts == *'139'* ]]; then
        echo -e "\n   >> NetBios"
        nmblookup -A "$ip"
        nbtscan "$ip"/30
        sudo nmap -sU -sV -T4 -oN netbiosScript --script nbstat.nse -p137 -Pn -n "$ip"
        continue
    fi

    cd ..
    echo -e "\nSe ha terminado el reconocimiento:) Buena suerte para encontrar vuln!!"
}

if [[ $1 == 'help' && $2 == "" ]]; then
    echo -e "\nEste archivo debe ser ejecutado como root"
    echo -e "\nEl primer parámetro debe ser el nombre del CTF"
    echo -e "\nEl segundo parámetro debe ser el IP de la maquina victima"
elif [[ $1 ]]; then
    dir

else
    echo -e "\nAlgo no ha salido bien"
    echo -e "\nEl primer parámetro debe ser el nombre del CTF"
    echo -e "\nEl segundo parámetro debe ser el IP de la maquina victima"
fi
