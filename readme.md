Скрипты автоматизации
====
##SSH
Проблема подключения putty к SSH через ключ

```
echo ‘PubkeyAcceptedAlgorithms +ssh-rsa’ >> /etc/ssh/sshd_config
```
##Веб
Методология

1) сбор информации (Краулинг)
nmap, dnscan, google, whatweb, burp spider
2) тестирование конфигурации (dirbuster, http method, )
3) тестирование механизмов идентификации (burp+secList)
4) тестирование механизмов аутентификации (Recovery)
5) тестирование механизмов авторизации (DirTraversal, Id Inc, FileBrute)
6) тестирование механизмов управления сессиями (Cookie, CSRF)
7) тестирование валидации входных данных (XSS, SQLi, XML, LDAP, XPATH, HTTP-Splitting)
8) тестирование обработки ошибок (ERROR handle)
9) тестирование на предмет некриптостойкого шифрования (SSL/TLS)
10) тестирование бизнес-логики приложения (Валидация данных, бизнес-логики, загрузка данных)
11) тестирование механизмов безопасности клиентской части(XSS,JavaScript-инъекции, Clickjacking, WebSockets; )![Uploading image.png…]()



