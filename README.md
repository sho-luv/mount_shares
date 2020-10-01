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
    
usage: mount_shares.py [-h] [-show] [-mount | -unmount] target

Tool to list share and or creat local dir and mount them for searching locally

positional arguments:
  target      [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help  show this help message and exit
  -show       Show all shares availabel on target regardless of user access
  -mount      Mount target shares locally
  -unmount    Unmount shares for target locally

```
