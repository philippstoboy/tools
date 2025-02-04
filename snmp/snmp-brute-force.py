#!/usr/bin/env python2
# Copyright curesec Gmbh ping@curesec.com

import argparse
import Queue
import threading

from pysnmp.entity.rfc3413.oneliner import cmdgen

myQueue = Queue.Queue()
myLock = threading.Lock()

auth_protocols = {
    "MD5": cmdgen.usmHMACMD5AuthProtocol,
    "SHA": cmdgen.usmHMACSHAAuthProtocol
}

priv_protocols = {
    "DES": cmdgen.usmDESPrivProtocol,
    "3DES": cmdgen.usm3DESEDEPrivProtocol,
    "AES128": cmdgen.usmAesCfb128Protocol,
    "AES192": cmdgen.usmAesCfb192Protocol,
    "AES256": cmdgen.usmAesCfb256Protocol
}

successful_auth_protocol = None
successful_priv_protocol = None
successful_logins = []

class SNMP_BRUTE_FORCE(threading.Thread):
    def run(self):
        while True:
            ip, username, auth_password, auth_protocol, priv_password, priv_protocol = myQueue.get()
            self.snmp_brute_force(ip, username, auth_password, auth_protocol, priv_password, priv_protocol)
            myQueue.task_done()

    def snmp_brute_force(self, ip, username, auth_password, auth_protocol, priv_password, priv_protocol):
        global passwords, port, version, timeout, retries, verbose

        if version == 1 or version == 2:
            if verbose:
                myLock.acquire()
                print "Testing community string: %s on %s" % (username, ip)
                myLock.release()
            status = snmp_connect(ip, username, None, None, None, None, port, version, timeout, retries, verbose)
            if status == "ok":
                myLock.acquire()
                print "Success on %s: %s" % (ip, username)
                myLock.release()
        else:
            global auth_protocols, priv_protocols
            global smartmode, successful_auth_protocol, successful_priv_protocol, successful_logins

            status = snmp_connect(
                ip,
                username,
                auth_password,
                auth_protocols.get(auth_protocol, cmdgen.usmNoAuthProtocol),
                priv_password,
                priv_protocols.get(priv_protocol, cmdgen.usmNoPrivProtocol),
                port, version, timeout, retries, verbose
            )

            if status == "ok":
                myLock.acquire()
                print "Success on %s: %s:%s[%s]:%s[%s]" % (ip, username, auth_password, auth_protocol, priv_password, priv_protocol)
                myLock.release()
                successful_logins.append(username)

def snmp_connect(ip, username, auth_password, auth_protocol, priv_password, priv_protocol, port, version, timeout, retries, verbose):
    cmdGen = cmdgen.CommandGenerator()

    if version == 1:
        authentication = cmdgen.CommunityData(username, mpModel=0)
    elif version == 2:
        authentication = cmdgen.CommunityData(username, mpModel=1)
    else:
        if auth_password is None:
            authentication = cmdgen.UsmUserData(username)
        elif priv_password is None:
            authentication = cmdgen.UsmUserData(username, auth_password, authProtocol=auth_protocol)
        else:
            authentication = cmdgen.UsmUserData(username, auth_password, priv_password, authProtocol=auth_protocol, privProtocol=priv_protocol)

    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
        authentication,
        cmdgen.UdpTransportTarget((ip, port), timeout=timeout, retries=retries),
        cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0)
    )

    if errorIndication:
        if verbose:
            print "Error on %s: %s" % (ip, errorIndication)
        return "timeout" if "timeout" in str(errorIndication) else "errorunknown"
    elif errorStatus:
        if verbose:
            print "ErrorStatus on %s: %s" % (ip, errorStatus)
        return "errorunknown"
    else:
        if verbose:
            for name, val in varBinds:
                print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
        return "ok"

def init(args):
    global port, version, timeout, retries, verbose, smartmode
    port = args.port
    version = args.version
    timeout = args.timeout
    retries = args.retries
    verbose = args.verbose
    smartmode = args.smartmode

    if version not in [1, 2, 3]:
        print "Error: Version must be 1, 2, or 3."
        return

    global ips
    ips = []
    if args.ip:
        ips = [args.ip]
    elif args.iplist:
        with open(args.iplist, "r") as ipfile:
            ips = [line.strip() for line in ipfile if line.strip()]

    if not ips:
        print "Error: No IPs provided."
        return

    global usernames
    usernames = []
    if args.username:
        usernames = [args.username]
    elif args.userfile:
        with open(args.userfile, "r") as userfile:
            usernames = [line.strip() for line in userfile if line.strip()]

    if not usernames:
        print "Error: No usernames provided."
        return

    global passwords
    passwords = []
    if version == 3:
        if args.password:
            if len(args.password) < 8:
                print "Error: Password too short: %s" % args.password
                return
            passwords = [args.password]
        elif args.passwordfile:
            with open(args.passwordfile, "r") as passwordfile:
                passwords = [line.strip() for line in passwordfile if len(line.strip()) >= 8]

    for _ in range(args.threads):
        worker_thread = SNMP_BRUTE_FORCE()
        worker_thread.setDaemon(True)
        worker_thread.start()

    for ip in ips:
        for username in usernames:
            myQueue.put((ip, username, None, None, None, None))

    myQueue.join()

def main():
    parser = argparse.ArgumentParser(description="SNMP Brute Force Tool")
    parser.add_argument("-ip", help="Single IP (e.g., 192.168.0.1)")
    parser.add_argument("--iplist", help="File with IPs (one per line)")
    parser.add_argument("-port", type=int, default=161, help="Default 161")
    
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument("-username", help="Single username (e.g., admin)")
    group1.add_argument("-userfile", help="File with usernames (one per line)")

    group2 = parser.add_mutually_exclusive_group(required=False)
    group2.add_argument("-password", help="Single password (e.g., secret)")
    group2.add_argument("-passwordfile", help="File with passwords (one per line)")

    parser.add_argument("-version", type=int, required=True, help="SNMP Version (1, 2, 3)")
    parser.add_argument("-timeout", type=int, default=3, help="Default 3")
    parser.add_argument("-retries", type=int, default=2, help="Default 2")
    parser.add_argument("-smartmode", action="store_true", default=False, help="Use smart mode for SNMPv3")
    parser.add_argument("-threads", type=int, default=1, help="Default 1")
    parser.add_argument("-v", action="store_true", dest="verbose", default=False, help="Verbose mode")
    
    args = parser.parse_args()
    init(args)

if __name__ == '__main__':
    main()
