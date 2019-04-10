#!/usr/bin/env python3
#
# Quick host enumeration script

import argparse
import os
import os.path
import pathlib
import re
import subprocess
import sys
import time

from pprint import pprint as pp

def info(msg):
    print("\n[*] {}".format(msg))

def err(msg):
    print("\n[-] {}".format(msg))

def ok(msg):
    print("\n[+] {}".format(msg))

def nmapScan(target):
    info("Running quick TCP nmap scan for {}".format(target))
    serv_dict = {}
    quick_scan = 'nmap -Pn -v0 --stats-every 1m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -p- ' + target + ' -oA ' + target + '/quick'
    print(quick_scan)
    os.system(quick_scan)

    open_tcp_ports = []

    f = open('{}/quick.gnmap'.format(target), 'r')
    for line in f:
        m = re.match('^Host:.*Ports:(.*)Ignored State:.*', line)

        if m:
            for portline in m.groups()[0].strip().split(','):
                open_tcp_ports.append(re.match('^(\d+)', portline.strip())[0])

    info("Running full TCP nmap scan on {} open ports".format(len(open_tcp_ports)))
    full_scan = 'nmap --stats-every 1m -Pn -v0 -A -sV -T4 -p' + ','.join(open_tcp_ports) + ' -oA ' + target + '/full ' + target
    print(full_scan)
    os.system(full_scan)

    all_ports = {'tcp': {}, 'udp': {}}

    f = open('{}/full.gnmap'.format(target), 'r')
    for line in f:
        m = re.match('^Host:.*Ports:(.*)(Ignored State:.*)?', line)
        
        if m:
            for portline in m.groups()[0].strip().split(','):
                (port,status,layer,owner,service,rpc,version,_) = portline.strip().split('/') 
                all_ports['tcp'][port] = {
                    'status': status,
                    'layer': layer,
                    'service': service,
                    'rpc info': rpc,
                    'version': version,
                }

    info('Please see {}/full.nmap for all nmap output (including script results)'.format(target))

    info('Consider running the following scan for UDP:')
    print('nmap -Pn -sU --stats-every 1m -oA {}/udp {}'.format(target, target))

    # Now for all the found ports go through them and see if we can run further nmap scripts
    # on them. If that is the case run it and store the results in a file in the same directory.
    # Beforehand print a number of scans to run also (by hand)

    pp(all_ports)

    handled_ports = []

    for p in all_ports['tcp']:
        port = all_ports['tcp'][p]
        if port['service'] in ['ftp', 'ftps']:
            ok('Found FTP(S) service on port {}: {}. Consider running the following commands:'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/ftp_{}.nmap {}'.format(p, target, p, target),
                'hydra -L /root/tools/SecLists/Usernames/Names/names.txt -P /root/tools/SecLists/Passwords/Common-Credentials/10k-most-common.txt -f -o {}/ftphydra.txt -u {} -s {} ftp'.format(target, p, p),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue

        if port['service'] in ['https', 'ssl/http']:
            ok('Found HTTPS service on port {}:{} as "{}". Consider running the following commands:'.format(p, port['service'], port['version']))
            commands = [
              '/root/tools/droopescan/droopescan scan drupal -u https://{}:{} --hide-progressbar | tee {}/logs/droopescan_{}'.format(target, p, target, p),
              '~/go/bin/gobuster -x html,asp,aspx,php,txt -k -u https://{}:{} -w /root/tools/SecLists/Discovery/Web-Content/common.txt -o {}/logs/gobuster_common_{}'.format(target, p, target, p),
              '~/go/bin/gobuster -x html,asp,php,aspx,txt -k -u https://{}:{} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o {}/logs/gobuster_{}'.format(target, p, target, p),
              'nikto -h https://{} -p {} -ssl | tee {}/logs/nikto_{}'.format(target, p, target, p),
              'nmap --script http-vuln\* -p {} -oN {}/logs/nmap_https_{}_vuln target'.format(p, target, target, p),
              'nmap -sV -sC -p {} -oN {}/logs/nmap_https_{} {}'.format(p, target, target, p),
              'curl -k https://{}:{}/robots.txt'.format(target, p),
              'nmap -p {} --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls {}'.format(p, target),
              '/root/tools/testssl.sh/testssl.sh https://{} | tee {}/logs/testssl_{}'.format(target, target, p),
              '/root/tools/wig/wig.py -w {}/logs/wig https://{}:{}'.format(target, target, p),
              'wpscan -u https://{}:{} --wordlist /root/tools/SecLists/Passwords/Common-Credentials/10k-most-common.txt --username admin | tee {}/logs/wpscan_brute'.format(target, p, target),
              'wpscan -u https://{}:{} | tee {}/logs/wpscan_{}'.format(target, p, target, p),
              'cewl -w {}/cewl_{}.txt https://{}:{}'.format(target, p, target, p),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue

        if 'http' in port['service']:
            ok('Found HTTP-like service on port {}:{} as "{}". Consider running the following commands:'.format(p, port['service'], port['version']))
            commands = [
              '/root/tools/droopescan/droopescan scan drupal -u http://{}:{} --hide-progressbar | tee {}/logs/droopescan_{}'.format(target, p, target, p),
              '~/go/bin/gobuster -x html,asp,aspx,php,txt -k -u http://{}:{} -w /root/tools/SecLists/Discovery/Web-Content/common.txt -o {}/logs/gobuster_common_{}'.format(target, p, target, p),
              '~/go/bin/gobuster -x html,asp,php,aspx,txt -k -u http://{}:{} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o {}/logs/gobuster_{}'.format(target, p, target, p),
              'nikto -h http://{} -p {} | tee {}/logs/nikto_{}'.format(target, p, target, p),
              'nmap --script http-vuln\* -p {} -oN {}/logs/nmap_http_{}_vuln target'.format(p, target, target, p),
              'nmap -sV -sC -p {} -oN {}/logs/nmap_http_{} {}'.format(p, target, target, p),
              'curl -k http://{}:{}/robots.txt'.format(target, p),
              'nmap -p {} --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls {}'.format(p, target),
              '/root/tools/wig/wig.py -w {}/logs/wig http://{}:{}'.format(target, target, p),
              'wpscan -u http://{}:{} --wordlist /root/tools/SecLists/Passwords/Common-Credentials/10k-most-common.txt --username admin | tee {}/logs/wpscan_brute'.format(target, p, target),
              'wpscan -u http://{}:{} | tee {}/logs/wpscan_{}'.format(target, p, target, p),
              'cewl -w {}/cewl_{}.txt http://{}:{}'.format(target, p, target, p),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue

        if port['service'] == 'ssh':
            ok('Found SSH service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/ssh_{}.nmap {}'.format(p, target, p, target),
                './check-ssh-username.py --port {} {} root'.format(p, target),
                'medusa -u root -P /usr/share/wordlists/rockyou.txt -e ns -h {} - {} -M ssh -f'.format(target, p),
                'medusa -U /roto/tools/SecLists/Usernames/top_shortlist.txt -P /root/tools/SecLists/Passwords/CommonCreds/best110.txt -e ns -h {} - {} -M ssh -f'.format(target, p),
                'hydra -l root -P /root/tools/SecLists/Passwords/CommonCreds/best110.txt {} ssh'.format(target),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue

        if port['service'] == 'vnc':
            ok('Found VNC service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/vnc_{}.nmap {}'.format(p, target, p, target),
                'hydra -P /root/tools/SecLists/Passwords/Common-Credentials/10k-most-common.txt -f -o {}/vnchydra.txt -u {} -s {} vnc'.format(target, p, p),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue

        if port['service'] == 'mongodb':
            ok('Found mongodb service on port {}'.format(p))
            commands = [
                'nmap -sV --script mongodb\* -p {} -oN {}/mongodb_{}.nmap {}'.format(p, target, p, target)
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if port['service'] == 'oracle':
            ok('Found oracle service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/oracle_{}.nmap {}'.format(p, target, p, target)
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if port['service'] == 'mysql':
            ok('Found mysql service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/mysql_{}.nmap {}'.format(p, target, p, target)
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if port['service'] == 'apanil':
            ok('Found cassandra service on port {}'.format(p))
            commands = [
                'nmap -sV --script=cassandra-* -p {} -oN {}/cassandra_{}.nmap {}'.format(p, target, p, target)
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if port['service'] == 'ms-sql':
            ok('Found mssql service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/mssql_{}.nmap {}'.format(p, target, p, target),
                'nmap -sV --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port={},smsql.username-sa,mssql.password-sa -p {} -oN {}/mssql_{}.nmap {}'.format(p, p, target, p, target),
                'nmap -n -Pn -p{} --script=ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=password,mssql.instance-port={},ms-sql-xp-cmdshell.cmd="ipconfig" {}'.format(p, p, target),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if port['service'] in ['microsoft-ds', 'netbios-ssn']:
            ok('Found netbios service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/smb_{}.nmap {}'.format(p, target, p, target),
                'nmap -n -sV -Pn -pT:139,{},U:137 --script=smb-enum-shares,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-ls,smb-mbenum,smb-os-discovery,smb-print-text,smb-security-mode,smb-server-stats,smb-system-info,smb-vuln* -oN {}/smb2_{}.nmap {}'.format(p, target, p, target),
                'nmap --script smb-vuln\* -p {} {}'.format(p, target),
                'smbclient -L\\\\ -N -I {}'.format(target),
                'smbclient -U guest -L\\\\ -N -I {}'.format(target),
                'enum4linux {} | tee {}/logs/enum4linux'.format(target, target),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if port['service'] == 'ldap':
            ok('Found ldap service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/ldap_{}.nmap {}'.format(p, target, p, target),
                'ldapsearch -H ldap://{} -x -LLL -s base -b "" supportedSASLMechanisms | tee {}/ldapsearch'.format(target, target),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if port['service'] in ['msrdp', 'ms-wbt-server']:
            ok('Found RDP service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV --script rdp\* -p {} -oN {}/rdp_{}.nmap {}'.format(p, target, p, target),
                'ncrack -vv --user Administrator -P /usr/share/wordlists/rockyou.txt rdp://{}'.format(target),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if port['service'] == 'smtp':
            ok('Found SMTP service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/smtp_{}.nmap {}'.format(p, target, p, target),
                'smtp-user-enum -M VRFY -U /root/tools/SecLists/Usernames/Names/names.txt -t {} -p {} | tee {}/logs/smtp-user-enum'.format(target, p, target),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if 'pop' in port['service']:
            ok('Found POP service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/pop_{}.nmap {}'.format(p, target, p, target)
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if 'imap' in port['service']:
            ok('Found IMAP service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/imap_{}.nmap {}'.format(p, target, p, target)
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if port['service'] in ['snmp', 'smux']:
            ok('Found SNMP service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/snmp_{}.nmap {}'.format(p, target, p, target),
                'onesixtyone {} public | tee {}/logs/onesixtyone'.format(target),
                'snmp-check {} | tee {}/logs/snmp-check'.format(target),
                'snmpwalk -c public -v1 {} | tee {}/logs/snmpwalk'.format(target, target),
                'snmpwalk -c public -v1 {} 1.3.6.1.4.1.77.1.2.25 | tee {}/logs/snmp_users'.format(target, target),
                'snmpwalk -c public -v1 {} 1.3.6.1.2.1.6.13.1.3 | tee {}/logs/snmp_ports'.format(target, target),
                'snmpwalk -c public -v1 {} 1.3.6.1.2.1.25.4.2.1.2 | tee {}/logs/snmp_process'.format(target, target),
                'snmpwalk -c public -v1 {} 1.3.6.1.2.1.25.6.3.1.2 | tee {}/logs/snmp_software'.format(target, target),
                'nmap --script snmp-brute --script-args snmp-brute.communitiesdb=/root/tools/SecLists/Discovery/SNMP/common-snmp-community-strings.txt -p {} {}'.format(p, target),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if port['service'] == 'telnet':
            ok('Found telnet service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/telnet_{}.nmap {}'.format(p, target, p, target),
                'medusa -U /root/offsecfw/wordlists/mirai_username.list -P /root/offsecfw/wordlists/mirai_password.list -e ns -h {} - {} -M telnet -t1 -f'.format(target, p),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue
        
        if port['service'] == 'domain' or 'dns' in port['service']:
            ok('Found DNS service on port {}: {}'.format(p, port['version']))
            commands = [
                'nmap -sV -sC -p {} -oN {}/logs/dns_{}.nmap {}'.format(p, target, p, target),
                'nmap -oN {}/logs/dns2_{}.nmap --script dns-zone-transfer,dns-srv-enum,dns-nsid,dns-check-zone,dns-service-discovery -p {} {}'.format(target, target, p, target),
                'dig axfr $DOMAIN @{}'.format(target),
                'host -l $DOMAIN {}'.format(target),
                'dnsrecon -d $DOMAIN -t axfr -n {}'.format(target),
            ]
            for k in commands:
                print("    " + k)
            handled_ports.append(p)
            continue

    # Now see if there are any ports we initially found, but have not handled yet
    for p in all_ports['tcp']:
        if p not in handled_ports:
            info('Port {}/tcp not recognized, this needs further investigation'.format(p))



if __name__ == '__main__':
    target = sys.argv[1] 
    info("Creating directory for {}'s reports".format(target))
    pathlib.Path(os.path.join(target, 'logs')).mkdir(parents=True, exist_ok=True)

    nmapScan(target)
