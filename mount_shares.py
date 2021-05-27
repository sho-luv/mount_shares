#!/usr/bin/python3

import os
import sys # Used by len, exit, etc
import argparse # Parser for command-line options, arguments and sub-commands
import logging
import ntpath
import subprocess
from cme.helpers.misc import gen_random_string

from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError
from impacket import smb
from impacket.smbconnection import SMBConnection # used impacket to connect to smb

smb_share_name = None
smb_server = None

############################################
# by Leon Johnson
#
# This program is used to mount cifs shares
# it will only list readable shars unless 
# -show option is provided. To mount shares
# It will create a directory named after
# the hostname and mount readable shares
# inside that dir.
#
# Debuging:
#       python -m pdb program.py
#
# this program will do the following:
#
# [x] list readable shares for supplied user
# [x] mount readable shares locally
# [ ] mount shares with spaces correctly
#     see CGYFS002 for example (might have fixed this indirectly)
# [x] verify cerds used are valid
# [x] remove crackmapexec dependency
# [ ] remove mount command dependency
# [ ] add hash support after remove mount dependency
#       Can't use mount command with hashes

# ----------------------------------
# Colors
# ----------------------------------
NOCOLOR='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHTGRAY='\033[0;37m'
DARKGRAY='\033[1;30m'
LIGHTRED='\033[1;31m'
LIGHTGREEN='\033[1;32m'
YELLOW='\033[1;33m'
LIGHTBLUE='\033[1;34m'
LIGHTPURPLE='\033[1;35m'
LIGHTCYAN='\033[1;36m'
WHITE='\033[1;37m'

def print_info():
        print(LIGHTBLUE+"SMB\t"+NOCOLOR+ipAddress+"\t"+options.port+"\t"+hostname, end = '')

def print_shares(connection):

        temp_dir = ntpath.normpath("\\" + gen_random_string()) 
        permissions = []
        shares = []
        output = []

        for share in connection.listShares():
            share_name = share['shi1_netname'][:-1]
            share_remark = share['shi1_remark'][:-1]
            share_info = {'name': share_name, 'remark': share_remark, 'access': []}
            read = False
            write = False

            try:
                connection.listPath(share_name, '*')
                read = True
                share_info['access'].append('READ')
            except SessionError:
                pass

            try:
                connection.createDirectory(share_name, temp_dir)
                connection.deleteDirectory(share_name, temp_dir)
                write = True
                share_info['access'].append('WRITE')
            except SessionError:
                pass

            permissions.append(share_info)

        for share in permissions:
            name   = share['name']
            remark = share['remark']
            perms  = share['access']

            #print((u'{:<15} {:<15} {}'.format(name, ','.join(perms), remark)))
            output = (u'{:<15} {:<15} {}'.format(name, ','.join(perms), remark))
            shares.append(''.join(output))

        if options.show is False:
            print_info()
            print(LIGHTGREEN+"\t[+] "+NOCOLOR+"Enumerated readable shares")
            print_info()
            print(YELLOW+"\tShare\t\tPermissions\tRemark"+NOCOLOR)
            print_info()
            print(YELLOW+"\t-----\t\t-----------\t------"+NOCOLOR)
            for share in shares:

                # no need to mount IPC share so we skip it!
                if re.search("IPC", share):
                   continue

                if re.search("READ", share):
                    print_info()
                    print(YELLOW+"\t"+share+NOCOLOR)
                    if options.m is True:
                        mount(share)
                        """
                        #print_info()
                        #print(LIGHTGREEN+"\t[+] "+NOCOLOR+"Mount shit!")
                        # check if dir already exist if not make it
                        if not os.path.exists(hostname):
                            os.makedirs(hostname)

                        # check if dir is empty
                        if not os.listdir(hostname):
                            try:
                                mount = 'mount -t cifs //'+hostname+' ./'+share+' -o username='+username+',password=\''+password+'\''
                                print("Command: "+mount)   # verbose
                                subprocess.call([mount], shell=True, stdout=subprocess.PIPE, universal_newlines=True)
                                print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                                print("Mounted //"+hostname+"/"+share+" Successfully!")
                            except:
                                print("Unable to mount share: "+hostname)
                                return
                        else:
                            print(RED+"[+] "+NOCOLOR, end = '')
                            print(hostname+" is not empty directory. Unable to mount")
                        """
                    elif options.u is True:
                        unmount(share)

        else:
            print_info()
            print(LIGHTGREEN+"\t[+] "+NOCOLOR+"Enumerated all shares")
            print_info()
            print(YELLOW+"\tShare\t\tPermissions\tRemark"+NOCOLOR)
            print_info()
            print(YELLOW+"\t-----\t\t-----------\t------"+NOCOLOR)
            for share in shares:
                print_info()
                print(YELLOW+"\t"+share+NOCOLOR)

        print(NOCOLOR)

def mount(shares):

    if re.search("READ", shares):
        share = re.findall(r"[\w\.\$\-]+", shares, flags=re.U)

        # pull out IP address and share name
        # directory = share[1]+"/"+share[4] # mount IP Address, breaks crackmapexec, becauses it thinks its a file to load. STOP USING CME!!!
        directory = hostname+"/"+share[0]   # mount hostname, requires /etc/resolve.conf < "search domain.local"

        # check if dir already exist if not make it
        if not os.path.exists(directory):
            os.makedirs(directory)

        # check if dir is empty
        if not os.listdir(directory):
            try:
                """
                # need to figure out how to use createMountPoint from smbconnection.py ->
                # https://github.com/SecureAuthCorp/impacket/blob/a16198c3312d8cfe25b329907b16463ea3143519/impacket/smbconnection.py#L861
                # I want to mount a remote network share locally using the createMountPoint function. 
                # However I'm unsure how to use this function. It's defined as follows:
                # def createMountPoint(self, tid, path, target):
                    #
                    #creates a mount point at an existing directory
                    #:param int tid: tree id of current connection
                    #:param string path: directory at which to create mount point (must already exist)
                    #:param string target: target address of mount point
                    
                #smbClient.createMountPoint( smbClient, directory, hostname)
                """
                mountCommand = 'mount -t cifs //'+directory+' ./'+directory+' -o username='+username+',password=\''+password+'\''
                #print("Command Attempted: ")   # verbose
                #print(mountCommand)
                subprocess.call([mountCommand], shell=True, stdout=subprocess.PIPE, universal_newlines=True)
                print_info()
                print(LIGHTGREEN+"\t[+] "+NOCOLOR, end = '')
                print("Mounted "+directory+" Successfully!")
            except:
                print("Unable to mount share: //"+directory)

        else:
            print_info()
            print(RED+"\t[+] "+NOCOLOR, end = '')
            print(directory+" is not empty directory. Unable to mount")
            return
                

def unmount(shares):

    if re.search("READ", shares):

        share = re.findall(r"[\w\.\$\-]+", shares, flags=re.U)
        directory = hostname+"/"+share[0]

        # check if dir exist
        if not os.path.exists(directory):
            print_info()
            print(RED+"\t[+] "+NOCOLOR, end = '')
            print("Can't unmount "+directory+" because it is doesn't exist!")
        else:
            try:
                #subprocess.call(['umount',directory], shell=True, stdout=subprocess.PIPE, universal_newlines=True)
                subprocess.call(['umount',directory])
                print_info()
                print(LIGHTGREEN+"\t[+] "+NOCOLOR, end = '')
                print("Unmounted: "+directory)
                subprocess.call(['rmdir',directory])
                print_info()
                print(LIGHTGREEN+"\t[+] "+NOCOLOR, end = '')
                print("Removed: "+directory)
            except:
                print_info()
                print("Unable to unmount share: "+directory)



if __name__ == '__main__':

    banner = """
        x-----------x
        | MOUNT     |
        | THEM      |
        | SHARES    |
        x-----------x
               ||
        (\__/) ||
        (•ㅅ•) ||
        / 　 づ
    """

    parser = argparse.ArgumentParser(description="Tool to list share and or creat local dir and mount them for searching locally")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    parser.add_argument('-show', action='store_true', help='Show all shares availabel on target regardless of user access')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-m','-mount', action='store_true', help='Mount target shares locally')
    group.add_argument('-u','-unmount', action='store_true', help='Unmount shares for target locally')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')



    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')


    if len(sys.argv)==1:
        print( banner )
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    try:
        smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port))
        if options.k is True:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip )
        else:
            smbClient.login(username, password, domain, lmhash, nthash)

        # get passed credentials
        userName, password, domain, lmhash, nthash, aesKey, TGT, TGS = smbClient.getCredentials()

        # get computer information
        hostname = smbClient.getServerName()
        ipAddress = smbClient.getRemoteHost()
        domain = smbClient.getServerDomain()
        fqdn = smbClient.getServerDNSDomainName()
        osVersion = smbClient.getServerOS()

        print_info()
        print(LIGHTBLUE+"\t[*] "+NOCOLOR, end = '')
        print(osVersion+" (name:"+hostname+") (domain:"+domain+")") 
        print_info()

        if not domain:
            print(LIGHTGREEN+"\t[+] "+NOCOLOR+hostname+"/"+userName+":"+password)
        else:
            print(LIGHTGREEN+"\t[+] "+NOCOLOR+domain+"/"+userName+":"+password)

        """
        print(smbClient.getServerName()) # get hostname
        print(smbClient.getRemoteHost()) # get IP address
        print(smbClient.getServerDomain()) # get domain name
        print(smbClient.getServerDNSDomainName()) # get full resolvable domain name
        print(smbClient.getServerDNSHostName()) # get domain name
        print(smbClient.getServerOS()) # get verion and build info
        #print(smbClient.getCredentials()) # get passed credentials
        #print(smbClient.listShares()) # get list shares
        smbClient.createMountPoint(smbClient, './', test_dir)
        """

        # default print only readable shares
        print_shares(smbClient)
        
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
