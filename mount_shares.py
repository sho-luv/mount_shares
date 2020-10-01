#!/usr/bin/python3.8

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

import os
import sys # Used by len, exit, etc
import argparse # Parser for command-line options, arguments and sub-commands


def print_shares(shares):
    if options.show is False:
        for share in shares:
            if re.search("READ", share):
                print(share)
    else:
        for share in shares:
            print(share)

def mount(shares):

    # grep out any READ shares from share
    #matching = [s for s in shares if r'$' in s]
    matching = [s for s in shares if 'READ' in s]

    if not matching:
        print(RED+"[+] "+NOCOLOR, end = '')
        print("No readable shares on "+address) 
        return
    else:
        for share in shares:

            # clean ANSI escape sequences from string
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            share = ansi_escape.sub('', share)
            
            # identify shares with read access
            if re.search("READ", share):
                share = re.findall(r"[\w\.\$]+", share, flags=re.U)

                # pull out IP address and share name
                directory = share[3]+"/"+share[4]

                # check if dir already exist if not make it
                if not os.path.exists(directory):
                    os.makedirs(directory)

                # check if dir is empty
                if not os.listdir(directory):
                    try:
                        mount = 'mount -t cifs //'+directory+' ./'+directory+' -o username='+username+',password='+password
                        subprocess.call([mount], shell=True, stdout=subprocess.PIPE, universal_newlines=True)
                        print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                        print("Mounted "+directory+" Successfully!")
                    except:
                        print("Unable to mount share: "+directory)
                        return
                else:
                    print(RED+"[+] "+NOCOLOR, end = '')
                    print(directory+" is not empty directory. Unable to mount")
                    

def unmount(shares):
    for share in shares:
        if re.search("READ", share):

            # clean ANSI escape sequences from string
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            share = ansi_escape.sub('', share)

            share = re.findall(r"[\w\.\$]+", share, flags=re.U)
            directory = share[3]+"/"+share[4]

            # check if dir exist
            if not os.path.exists(directory):
                print(RED+"[+] "+NOCOLOR, end = '')
                print("Can't unmount "+directory+" because it is doesn't exist!")
            else:
                # check if dir is empty
                if not os.listdir(directory):
                    print(RED+"[+] "+NOCOLOR, end = '')
                    print("Can't unmount "+directory+" because it is already empty!")
                else:
                    try:
                        #subprocess.call(['umount',directory], shell=True, stdout=subprocess.PIPE, universal_newlines=True)
                        subprocess.call(['umount',directory])
                        print()
                        print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                        print("Unmounted: "+directory)
                        subprocess.call(['rmdir',directory])
                        print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                        print("Removed: "+directory)
                    except:
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
    group.add_argument('-mount', action='store_true', help='Mount target shares locally')
    group.add_argument('-unmount', action='store_true', help='Unmount shares for target locally')

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

    import subprocess

    # Look at removing dependency on CrackMapExec
    process = subprocess.run(['cme','smb', address,'-u',username,'-p',password,'--shares'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
    output = process.stdout
    shares = output.splitlines()

    print_shares(shares)

    if options.mount is True:
        mount(shares)
    elif options.unmount is True:
        unmount(shares)
