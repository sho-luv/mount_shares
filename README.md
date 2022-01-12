<h4 align="center">mount_shares</h4>
<p align="center">
  <a href="https://twitter.com/sho_luv">
    <img src="https://img.shields.io/badge/Twitter-%40sho_luv-blue.svg">
    <img src="https://img.shields.io/badge/python-3+-blue.svg">
  </a>
</p>

# mount_shares.py
Are you tired of manually mounting shares one by one? Do you have a hard time remembering the syntax to mount shares or to search shares with tools like CrackMapExec!? 
Well you are not alone!

This tool is modled after the Impacket suite. It takes a username and password and target information. It then checks to see if the usernamem and password provided allow 
access to any shares on the target system you provided. If there are any readable shares it will list them. 

But wait there is more!

If you provide the -mount option it will then mount all the shares you have read access to locally! So now you can simply grep for passwords, SSNs, Credit Card Data, 
whatever it is you are looking for till your little lazy heart is content! 

# Usage
``` 
./mount_shares.py 
        x-----------x
        | MOUNT     |
        | THEM      |
        | SHARES    |
        x-----------x
               ||
        (\__/) ||
        (•ㅅ•) ||
        / 　 づ
    
usage: mount_shares.py [-h] [-m | -u | -show] [-debug] [-write] [-A authfile] [-port [destination port]] target

Tool to list shares and/or create local dir to mount them for searching locally

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help            show this help message and exit
  -m, -mount            Mount target shares locally
  -u, -unmount          Unmount shares for target locally
  -show                 Show all shares available (Default only show READ access shares)
  -debug                Turn DEBUG output ON
  -write                Mount shares as WRITABLE (Default READ ONLY)

authentication:
  -A authfile           smbclient/mount.cifs-style authentication file. See smbclient man page's -A option.

connection:
  -port [destination port]
                        Destination port to connect to SMB Server


```
## Example:
![mount-shares](https://user-images.githubusercontent.com/1679089/149044395-46484e41-3086-45ed-98e3-6ad3b47a0826.gif)

