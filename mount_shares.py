#!/usr/bin/python3

import os
import re
import sys # Used by len, exit, etc
import tempfile
import argparse # Parser for command-line options, arguments and sub-commands
import socket
import logging
import ntpath
import subprocess
from impacket.smb import SMB_DIALECT
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

        # NOTE: do not logoff here -- the connection is reused by
        # print_shares() to enumerate shares.

        return True


    def print_info(self):
        ip = self.ipAddress if self.ipAddress else self.hostname
        print(LIGHTBLUE+"SMB\t"+NOCOLOR+ip+"\t"+self.args.port+"\t"+self.hostname, end = '')

    def print_host_info(self):
        self.print_admin()
        print(self.osVersion+" "+str(self.os_arch)+" (name:"+self.hostname+") (domain:"+
            self.fqdn+") (signing:"+str(self.signing)+") (SMBv1:"+
            str(self.smbv1)+")"+NOCOLOR)


    def _format_share(self, share_info):
        # single source of truth for the display line
        return u'{:<15} {:<15} {}'.format(
            share_info['name'], ','.join(share_info['access']), share_info['remark'])

    def print_shares(self):

        permissions = []

        for share in self.conn.listShares():
            share_name = share['shi1_netname'][:-1]
            share_remark = share['shi1_remark'][:-1]
            share_info = {'name': share_name, 'remark': share_remark, 'access': []}

            # Test READ access. Only ACCESS_DENIED (SessionError) means "no read";
            # any other error is a transient/unexpected failure that must NOT abort
            # enumeration of the remaining shares.
            try:
                self.conn.listPath(share_name, '*')
                share_info['access'].append('READ')
            except SessionError:
                pass
            except Exception as e:
                logging.debug('Error listing share {}: {}'.format(share_name, e))

            # Test WRITE access the same way.
            try:
                self.conn.createDirectory(share_name, "\\mytempdir_washere")
                self.conn.deleteDirectory(share_name, "\\mytempdir_washere")
                share_info['access'].append('WRITE')
            except SessionError:
                pass
            except Exception as e:
                logging.debug('Error write-testing share {}: {}'.format(share_name, e))

            permissions.append(share_info)

        if options.show is False:
            self.print_info()
            print(LIGHTGREEN+"\t[+] "+NOCOLOR+"Enumerated readable shares")
            self.print_info()
            print(YELLOW+"\tShare\t\tPermissions\tRemark"+NOCOLOR)
            self.print_info()
            print(YELLOW+"\t-----\t\t-----------\t------"+NOCOLOR)
            for share_info in permissions:

                # no need to mount IPC share so we skip it!
                if share_info['name'].upper() == 'IPC$':
                    continue

                # default mode only lists/mounts shares we can read
                if 'READ' not in share_info['access']:
                    continue

                line = self._format_share(share_info)

                if options.m is True:
                    self.print_info()
                    print(YELLOW+"\t"+line+NOCOLOR, end='')
                    if not self.mount(share_info):
                        print(RED+"\t[+] "+NOCOLOR, end = '')
                        print("Can't mount "+share_info['name']+" because it already exists!")

                elif options.u is True:
                    self.print_info()
                    print(YELLOW+"\t"+line+NOCOLOR, end='')
                    self.unmount(share_info)

                else:
                    self.print_info()
                    print(YELLOW+"\t"+line+NOCOLOR)

            # clean created hostname dir if it ended up empty
            if options.u is True:
                if os.path.exists(self.hostname) and not os.listdir(self.hostname):
                    try:
                        os.rmdir(self.hostname)
                    except OSError:
                        pass

        else:
            self.print_info()
            print(LIGHTGREEN+"\t[+] "+NOCOLOR+"Enumerated all shares")
            self.print_info()
            print(YELLOW+"\tShare\t\tPermissions\tRemark"+NOCOLOR)
            self.print_info()
            print(YELLOW+"\t-----\t\t-----------\t------"+NOCOLOR)
            for share_info in permissions:
                self.print_info()
                print(YELLOW+"\t"+self._format_share(share_info)+NOCOLOR)

        print(NOCOLOR)

    def _write_credentials_file(self):
        # Reuse the exact credentials that authenticated during enumeration, and
        # hand them to mount.cifs via a 0600 credentials file rather than on the
        # command line. This keeps the password out of `ps` output and, unlike
        # the "-o password=" form, tolerates passwords containing commas.
        lines = 'username={}\n'.format(username)
        if password:
            lines += 'password={}\n'.format(password)
        if domain:
            lines += 'domain={}\n'.format(domain)

        fd, path = tempfile.mkstemp(prefix='.mount_shares_cred_')
        try:
            os.write(fd, lines.encode('utf-8'))
        finally:
            os.close(fd)
        os.chmod(path, 0o600)
        return path

    def _local_mount_dir_exists(self, share):
        # Check the PARENT directory's listing instead of stat-ing the mountpoint
        # itself. If a share is mounted but the SMB connection has gone stale,
        # stat()/os.path.exists() on the mountpoint fails and would wrongly report
        # "doesn't exist" -- causing us to skip the very cleanup we need, or to try
        # to recreate a directory that is already there. Reading the parent's
        # entries never touches the (possibly dead) mounted filesystem.
        try:
            return share in os.listdir(self.hostname)
        except OSError:
            return False

    def mount(self, share_info):
        # Returns False only when the local directory already exists (nothing
        # attempted); True whenever a mount was attempted (success or failure is
        # reported inline).
        share = share_info['name']

        # Name the local mount point after the hostname/share. We mount using the
        # IP address so we don't depend on name resolution, but fall back to the
        # hostname if the host never resolved.
        hostnameDirectory = os.path.join(self.hostname, share)
        server = self.ipAddress if self.ipAddress else self.hostname
        source = '//{}/{}'.format(server, share)

        if self._local_mount_dir_exists(share):
            return False

        os.makedirs(hostnameDirectory)

        # Build the command as an argument list (NO shell=True). This is what makes
        # share names containing spaces and special characters ($ & ( ) ' etc.)
        # work correctly. Credentials go through a temp file (see below).
        cred_path = self._write_credentials_file()
        opts = 'credentials={}'.format(cred_path)
        if not options.write:
            cmd = ['mount', '-r', '-t', 'cifs', source, hostnameDirectory, '-o', opts]
        else:
            cmd = ['mount', '-t', 'cifs', source, hostnameDirectory, '-o', opts]

        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True)
        finally:
            # mount.cifs has already read the file by the time run() returns.
            try:
                os.remove(cred_path)
            except OSError:
                pass

        if result.returncode == 0:
            print(LIGHTGREEN+"\t[+] "+NOCOLOR, end = '')
            if not options.write:
                print("Mounted "+hostnameDirectory+" Successfully!")
            else:
                print("Mounted "+hostnameDirectory+" Successfully!", end="")
                print(RED+" Caution mounted WRITABLE shares!"+NOCOLOR)
        else:
            # The mount FAILED. Remove the empty directory we just created so it
            # doesn't masquerade as a successful-but-empty mount.
            try:
                os.rmdir(hostnameDirectory)
            except OSError:
                pass
            error = result.stderr.strip() if result.stderr else 'mount command failed'
            print(RED+"\t[!] "+NOCOLOR, end = '')
            print("Unable to mount "+hostnameDirectory+": "+error)

        return True


    def unmount(self, share_info):
        share = share_info['name']
        directory = os.path.join(self.hostname, share)

        # Use the parent-listing check, NOT os.path.exists(directory): a stale
        # mountpoint (dead SMB session) fails stat() and would look like it
        # "doesn't exist", stranding a mount we could otherwise clean up.
        if not self._local_mount_dir_exists(share):
            print(RED+"\t[+] "+NOCOLOR, end = '')
            print("Can't unmount "+directory+" it doesn't exist!")
            return

        result = subprocess.run(['umount', directory],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)

        # A busy or stale mount fails a plain umount; retry with a lazy detach
        # (umount -l), which cleanly removes stale CIFS mountpoints.
        if result.returncode != 0:
            lazy = subprocess.run(['umount', '-l', directory],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True)
            if lazy.returncode == 0:
                result = lazy

        if result.returncode == 0:
            print(LIGHTGREEN+"\t[+] "+NOCOLOR, end = '')
            print("Unmounted/Removed: "+directory)
            try:
                os.rmdir(directory)
            except OSError:
                pass
        else:
            error = result.stderr.strip() if result.stderr else 'umount command failed'
            print(RED+"\t[!] "+NOCOLOR, end = '')
            print("Unable to unmount "+directory+": "+error)


def get_os_arch(self):
    try:
        stringBinding = r'ncacn_ip_tcp:{}[135]'.format(self.ipAddress)
        transport = DCERPCTransportFactory(stringBinding)
        transport.set_connect_timeout(5)
        dce = transport.get_dce_rpc()
        dce.connect()
        try:
            dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
        except DCERPCException as e:
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

    banner = r"""
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
            ='[[domain/]username[:password]@]<targetName or address>')

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

    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)

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
