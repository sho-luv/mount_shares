#!/usr/bin/python3

import os
import sys # Used by len, exit, etc
import argparse # Parser for command-line options, arguments and sub-commands
import socket
import logging
import subprocess
import re
from impacket import smb
#from impacket.smb3structs import FILE_READ_DATA # unsure if I need this...
#from impacket.smbconnection import SessionError
from impacket.smbconnection import SMBConnection, SessionError
#from impacket.smbconnection import SMBConnection # used impacket to connect to smb
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP

############################################
# by Leon Johnson aka @sho_luv
#
# This code uses Impacket library to mount remote 
# shares locally. This allows us to use tools like
# grep and other linux tools to search the shares
# for sensitive information.
#
# This program is used to mount cifs shares
# it will only list readable shares unless 
# -show option is provided. To mount shares
# It will create a directory named after
# the hostname and mount readable shares
# inside that dir.
#
# Debugging:
#       python -m pdb program.py
#
# todo:
#
# [x] list readable shares for supplied user
# [x] mount readable shares locally
# [x] mount shares with spaces correctly
# [x] verify creds used are valid
# [x] remove crackmapexec dependency
# [x] fixed /etc/resolve.conf dependency
# [x] change default to READONLY changed with -write option
# [x] added auth file support
# [x] change code to clean up all created dirs on unmount command
# [ ] add kerberos support to mounting shares
#       this will allow pth mounting of shares
#       sudo mount -t cifs -o sec=krb5,vers=3.0 '//SERVER.DOMAIN.LOCAL/SHARE' /mnt/share
# [ ] remove mount command dependency if possible
# [ ] add hash support after remove mount dependency or via kerberos
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


READ = 'READ'

# set logging error to remove ERROR:root:
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# smb share vars
smb_share_name = None
smb_server = None

class smb:

    def __init__(self, args, domain, username, password, hostname):
        self.args = args
        self.domain = domain
        self.username = username
        self.password = password
        self.hostname = hostname
        self.osVersion = ""
        self.os_arch = 0
        self.smbv1 = None
        self.signing = False
        self.admin_privs = False
        self.smb_share_name = smb_share_name

        try:
            self.ipAddress = socket.gethostbyname(hostname)
        except Exception as e:
            if options.verbose:
                logger.error(RED+"Host "+hostname+" did not resolve."+NOCOLOR)
            self.ipAddress = None

    def print_admin(self):
        if self.admin_privs:
            print("\t"+LIGHTGREEN+"[*] "+NOCOLOR, end = '')
        else:
            print("\t"+BLUE+"[*] "+NOCOLOR, end = '')


    def smbv1_conn(self):
        try:
            self.conn = SMBConnection(self.hostname, self.hostname, None,  self.args.port, preferredDialect=SMB_DIALECT, timeout=self.args.timeout)
            self.smbv1 = True
        except socket.error as e:
            if str(e).find('Connection reset by peer') != -1:
                logging.debug('SMBv1 might be disabled on {}'.format(self.hostname))
            return False
        except (Exception, NetBIOSTimeout) as e:
            logging.debug('Error creating SMBv1 connection to {}: {}'.format(self.hostname, e))
            return False

        return True

    def smbv3_conn(self):
        try:
            self.conn = SMBConnection(self.hostname, self.hostname, None, self.args.port, timeout=self.args.timeout)
            self.conn = SMBConnection(self.hostname, self.hostname, sess_port=int(self.args.port), timeout=self.args.timeout)

            self.smbv1 = False
        except socket.error:
            return False
        except (Exception, NetBIOSTimeout) as e:
            logging.debug('Error creating SMBv3 connection to {}: {}'.format(self.hostname, e))
            return False

        return True

    def create_conn_obj(self):
        if self.smbv1_conn():
            return True
        elif self.smbv3_conn():
            return True

        return False

    
    def get_info(self):
        try:
            self.conn.login(self.username, self.password, self.domain)

        except Exception as e:
            try:
                self.conn.login('', '')
            except SessionError as e:
                pass
            if options.verbose:
                logger.error(RED+"Connection to host "+self.hostname+" timedout"+NOCOLOR)

        # get computer information
        self.osVersion = self.conn.getServerOS()
        self.hostname = self.conn.getServerName()
        self.domain = self.conn.getServerDomain()
        self.signing = self.conn.isSigningRequired()
        self.fqdn = self.conn.getServerDNSDomainName()
        self.os_arch = get_os_arch(self)
        try:
            self.conn.connectTree("C$")
            self.admin_privs = True
        except Exception as e:
            pass

        try:
            smb_conn.logoff()
        except:
            pass

        return True


    def print_info(self):
        print(LIGHTBLUE+"SMB\t"+NOCOLOR+self.ipAddress+"\t"+self.args.port+"\t"+self.hostname, end = '')

    def print_host_info(self):
        self.print_admin()
        print(self.osVersion+" "+str(self.os_arch)+" (name:"+self.hostname+") (domain:"+
            self.fqdn+") (signing:"+str(self.signing)+") (SMBv1:"+
            str(self.smbv1)+")"+NOCOLOR)


    def print_shares(self):

            permissions = []
            shares = []
            output = []

            for share in self.conn.listShares():
                share_name = share['shi1_netname'][:-1]
                share_remark = share['shi1_remark'][:-1]
                share_info = {'name': share_name, 'remark': share_remark, 'access': []}
                read = False
                write = False

                try:
                    self.conn.listPath(share_name, '*')
                    read = True
                    share_info['access'].append('READ')
                except SessionError:
                    pass

                try:
                    self.conn.createDirectory(share_name, "\\mytempdir_washere")
                    self.conn.deleteDirectory(share_name, "\\mytempdir_washere")
                    write = True
                    share_info['access'].append('WRITE')
                except SessionError:
                    pass

                permissions.append(share_info)

            for share in permissions:
                name   = share['name']
                remark = share['remark']
                perms  = share['access']

                output = (u'{:<15} {:<15} {}'.format(name, ','.join(perms), remark))
                shares.append(''.join(output))

            if options.show is False:
                self.print_info()
                print(LIGHTGREEN+"\t[+] "+NOCOLOR+"Enumerated readable shares")
                self.print_info()
                print(YELLOW+"\tShare\t\tPermissions\tRemark"+NOCOLOR)
                self.print_info()
                print(YELLOW+"\t-----\t\t-----------\t------"+NOCOLOR)
                for share in shares:
                    # no need to mount IPC share so we skip it!
                    if re.search("IPC", share):
                        continue

                    if re.search("READ", share):
                        if options.m is True:
                            self.print_info()
                            print(f"{YELLOW}\t{share}{NOCOLOR}")
                            share_name = share.split("   ")[0]
                            if not self.mount(share):
                                print(f"{RED}\t[+] {NOCOLOR}Failed to mount {share_name}.")

                        elif options.u is True:
                            self.print_info()
                            print(YELLOW+"\t"+share+NOCOLOR, end='')
                            self.unmount(share)

                        else:
                            self.print_info()
                            print(YELLOW+"\t"+share+NOCOLOR)

                # clean created hostname dir
                if options.u is True:
                    if os.path.exists(self.hostname):
                        if not os.listdir(self.hostname):
                            os.rmdir(self.hostname)

            else:
                self.print_info()
                print(LIGHTGREEN+"\t[+] "+NOCOLOR+"Enumerated all shares")
                self.print_info()
                print(YELLOW+"\tShare\t\tPermissions\tRemark"+NOCOLOR)
                self.print_info()
                print(YELLOW+"\t-----\t\t-----------\t------"+NOCOLOR)
                for share in shares:
                    self.print_info()
                    print(YELLOW+"\t"+share+NOCOLOR)

            print(NOCOLOR)

    def mount(self, shares):
        if re.search("READ", shares) == False:
            print(f"No read permissions found for this share, skipping.{NOCOLOR}")
            return False
            # convert string into list
        share = re.findall(r"[\w\.\$\-]+", shares, flags=re.U)

        # use index to extract share name with spaces until READ element in list
        temp = share.index(READ)
        share = share[:temp]
        share = ' '.join(share)

        # I created two variables because I wanted to name the share after the hostname
        # however if the hostname doesn't resolve the mount command errors out
        # so I use the IP address to mount the share and the hostname to name the local shares
        # otherwise you have to ensure the hostname resolves in /etc/resolve.conf
        # by adding search i.e. echo -n "search domain.local" >> /etc/resolve.conf
        hostnameDirectory = self.hostname+"/"+share+""

        # added qoutes for shares with spaces
        ipDirectory = self.ipAddress+"/\""+share+"\""

        # check if dir already exist if not make it
        try:
            # remove the empty dir, if it exists
            os.rmdir(hostnameDirectory)
        except FileNotFoundError:
            # do nothing, this is what we want to see
            pass
        except OSError:
            print(f"\t{RED}[-] {NOCOLOR}The directory '{hostnameDirectory}' exists and is not empty, clear this first, skipping.",
                  file=sys.stderr)
            return False


        os.makedirs(hostnameDirectory)
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
            if not options.write:
                mountCommand = 'mount -r -t cifs //'+ipDirectory+' ./"'+hostnameDirectory+'" -o username='+username+',password=\''+password+'\''
            else:
                print(RED+" Caution mounted WRITABLE shares!"+NOCOLOR, end="")
                mountCommand = 'mount -t cifs //'+ipDirectory+' ./"'+hostnameDirectory+'" -o username='+username+',password=\''+password+'\''
            result = subprocess.call([mountCommand], shell=True, stdout=subprocess.PIPE, universal_newlines=True)
            if result == 0:  # it returned a 0, therefore, success
                print(f"{LIGHTGREEN}\t[+] {NOCOLOR}Mounted {hostnameDirectory} Successfully!")
                return True
            else:
                print(f"{RED}Received error code {result} while trying to mount "
                      f"{hostnameDirectory}, skipping this mount.{NOCOLOR}",
                      file=sys.stderr)
                # removing the empty directory we created
                os.rmdir(hostnameDirectory)
        except Exception as err:
            print(f"Unable to mount share: //{hostnameDirectory}, error: {err}", file=sys.stderr)

        return False

    def unmount(self, shares):
        if re.search("READ", shares):

            share = re.findall(r"[\w\.\$\-]+", shares, flags=re.U)
            # use index to extract share name with spaces until READ element in list
            temp = share.index(READ)
            share = share[:temp]
            share = ' '.join(share)

            directory = self.hostname+"/"+share

            # check if dir exist
            if not os.path.exists(directory):
                print(f"{RED}\t[+] {NOCOLOR} Can't unmount {directory} it doesn't exist!", file=sys.stderr)
            else:
                try:
                    subprocess.call(['umount',directory])
                    print(LIGHTGREEN+"\t[+] "+NOCOLOR, end = '')
                    print("Unmounted/Removed: "+directory)
                    subprocess.call(['rmdir',directory])
                except:
                    print("Unable to unmount share: "+directory)

def do_mounts(options, domain, password, target_var):
    targets = []
    if os.path.exists(target_var):  # check to see if a file was provided instead of an address
        with open(target_var,'r') as fh:
            targets = [line.strip() for line in fh.readlines()]
    else:
        targets.append(target_var)
    for address in targets:
        try:
            share = smb(options, domain, username, password, address)
            if share.create_conn_obj():
                share.get_info()
            else:
                print(YELLOW+"Can't connect to "+share.hostname+NOCOLOR)
                exit()

            share.print_info()
            share.print_host_info()
            if username:
                share.print_shares()

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))

def get_os_arch(self):
    try:
        stringBinding = r'ncacn_ip_tcp:{}[135]'.format(self.ipAddress)
        transport = DCERPCTransportFactory(stringBinding)
        transport.set_connect_timeout(5)
        dce = transport.get_dce_rpc()
        dce.connect()
        try:
            dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
        except (DCERPCException, e):
            if str(e).find('syntaxes_not_supported') >= 0:
                dce.disconnect()
                return "x32"
        else:
            dce.disconnect()
            return "x64"

    except Exception as e:
        logging.debug('Error retrieving os arch of {}: {}'.format(self.hostname, str(e)))

    return 0
        

class AuthFileSyntaxError(Exception):

    '''raised by load_smbclient_auth_file if it encounters a syntax error
    while loading the smbclient-style authentication file.'''

    def __init__(self, path, lineno, reason):
        self.path=path
        self.lineno=lineno
        self.reason=reason

    def __str__(self):
        return 'Syntax error in auth file %s line %d: %s' % (
            self.path, self.lineno, self.reason )

def load_smbclient_auth_file(path):

    '''Load credentials from an smbclient-style authentication file (used by
    smbclient, mount.cifs and others).  returns (domain, username, password)
    or raises AuthFileSyntaxError or any I/O exceptions.'''

    lineno=0
    domain=None
    username=None
    password=None
    for line in open(path):
        lineno+=1

        line = line.strip()

        if line.startswith('#') or line=='':
            continue

        parts = line.split('=',1)
        if len(parts) != 2:
            raise AuthFileSyntaxError(path, lineno, 'No "=" present in line')

        (k,v) = (parts[0].strip(), parts[1].strip())

        if k=='username':
            username=v
        elif k=='password':
            password=v
        elif k=='domain':
            domain=v
        else:
            raise AuthFileSyntaxError(path, lineno, 'Unknown option %s' % repr(k))

    return (domain, username, password)


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

    parser = argparse.ArgumentParser(description
            ="Tool to list shares and/or create local dir to mount them for searching locally")

    parser.add_argument('target', action='store', help
            ='[[domain/]username[:password]@]<targetName, address, or line-delimited file containing list of hosts>') 

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-m','-mount', action='store_true', help
            ='Mount target shares locally')
    group.add_argument('-u','-unmount', action='store_true', help
            ='Unmount shares for target locally')
    group.add_argument('-show', action='store_true', help
            ='Show all shares available (Default only show READ access shares)')

    parser.add_argument('-debug', action='store_true', help
            ='Turn DEBUG output ON')
    parser.add_argument('-write', action='store_true', help
            ='Mount shares as WRITABLE (Default READ ONLY)')
    parser.add_argument('-v','--verbose', action='store_true', help='view verbose messages')

    group = parser.add_argument_group('authentication')
    group.add_argument('-A', action="store", metavar = "authfile", help
            ="smbclient/mount.cifs-style authentication file. "
             "See smbclient man page's -A option.")
    group = parser.add_argument_group('connection')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default
            ='445', metavar="destination port", help
            ='Destination port to connect to SMB Server')
    group.add_argument("-t","-timeout", dest='timeout', help="SMB connection timeout, default 3 secondes", type=int, default=3)


    if len(sys.argv)==1:
        print( banner )
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    # In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if options.A is not None:
        (domain, username, password) = load_smbclient_auth_file(options.A)
        logging.debug('loaded smbclient auth file: domain=%s, username=%s, password=%s' % (repr(domain), repr(username), repr(password)))

    if domain is None:
        domain = ''

    if password == '' and username != '':
        from getpass import getpass
        password = getpass("Password:")
    do_mounts(options, domain, password, address)
