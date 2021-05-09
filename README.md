# Graduation-study

## Description

This is one of my graduation-study record.  
I studied about honeypot on HTTPS.
This is dirty code, but I leave it as a memorial. 

## Contents

```
.  
├── GeoLite2-City_20201027  
│   └── GeoLite2-City.mmdb  
├── README.md  
├── hpot.py  
└── sample_log  
    ├── 6_https_1208  
    ├── 6_https_1208.pcap  
    ├── 7_http_1208  
    ├── 7_http_1208.pcap  
    ├── 7_https_1208  
    ├── 7_https_1208.pcap  
    ├── 8_http_1208  
    ├── 8_http_1208.pcap  
    ├── 8_https_1208  
    └── 8_https_1208.pcap
```

## How to use 'hpot.py'
Option name is sloppy !

***- parse honeypot-log***
> < option l >
```
$ python3 hpot.py -l sample_log/8_https_1208
sample_log/8_https_1208
/ 1 /
[2020-12-08 01:09:06+0900] 128.14.133.58 192.168.0.8:443 "GET / HTTP/1.1" 200 False
GET / HTTP/1.1
Host: 133.14.14.248
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36
Accept: */*
Accept-Encoding: gzip

/ 2 /
[2020-12-08 02:26:10+0900] 205.185.119.203 192.168.0.8:443 "GET / HTTP/1.1" 200 False
GET / HTTP/1.1
Host: 133.14.14.248
User-Agent: Mozilla/5.0 (compatible, MSIE 10.0, Windows NT, DigExt)
Connection: close
Accept-Encoding: gzip

...
```
> < option ll >  
※ multiple arguments can be specified
```
$ python3 hpot.py -ll sample_log/8_https_1208
sample_log/8_https_1208
	128.14.133.58	: GET /
	205.185.119.203	: GET /
	192.241.234.126	: GET /actuator/health
	95.214.11.231	: POST /autodiscover
	95.214.11.231	: POST /autodiscover
	185.234.219.205	: GET /
    ...
```

> < option lf >  
※ multiple arguments can be specified
```
$ python3 hpot.py -lf sample_log/8_https_1208
ip or req -> ip
Input target you want to find : 91.241.19.84
sample_log/8_https_1208
	found! -> 91.241.19.84 : POST /api/jsonws/invoke
sample_log/8_https_1208
	found! -> 91.241.19.84 : POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
sample_log/8_https_1208
	found! -> 91.241.19.84 : GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
```
```
$ python3 hpot.py -lf sample_log/8_https_1208
ip or req -> req
Input target you want to find : autodiscover
sample_log/8_https_1208
	found! -> 95.214.11.231 : POST /autodiscover
sample_log/8_https_1208
	found! -> 95.214.11.231 : POST /autodiscover
```

> < option ln >  
※ multiple arguments can be specified
```
$ python3 hpot.py -ln sample_log/8_https_1208
24
アメリカ合衆国	10	42.0%
ロシア	9	38.0%
リトアニア共和国	2	8.0%
ポーランド共和国	1	4.0%
ドイツ連邦共和国	1	4.0%
フランス共和国	1	4.0%
```

> < option cia >  
※ multiple arguments can be specified
```
$ python3 hpot.py -cia sample_log/8_https_1208
"GET / HTTP/1.1"
	128.14.133.58	アメリカ合衆国
	205.185.119.203	アメリカ合衆国
	185.234.219.205	ポーランド共和国
	128.14.134.134	アメリカ合衆国
	184.105.139.67	アメリカ合衆国
	71.6.232.7	アメリカ合衆国
	193.118.55.146	ドイツ連邦共和国
	192.35.168.32	アメリカ合衆国
	192.241.219.38	アメリカ合衆国
	92.222.221.49	フランス共和国
"GET /actuator/health HTTP/1.1"
	192.241.234.126	アメリカ合衆国
"GET /console/ HTTP/1.1"
	91.241.19.84	ロシア
...
```

> < option cip >  
※ multiple arguments can be specified
```
$ python3 hpot.py -cip sample_log/8_https_1208
input country: アメリカ合衆国
make out in current directory as cip_アメリカ合衆国.txt

"GET / HTTP/1.1"  :  7
"GET /actuator/health HTTP/1.1"  :  1
"GET /owa/auth/logon.aspx?url=https%3a%2f%2f1%2fecp%2f HTTP/1.1"  :  1
"GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1"  :  1
```
```
$ cat cip_アメリカ合衆国.txt
"GET / HTTP/1.1"
	128.14.133.58	アメリカ合衆国
	205.185.119.203	アメリカ合衆国
	128.14.134.134	アメリカ合衆国
	184.105.139.67	アメリカ合衆国
	71.6.232.7	アメリカ合衆国
	192.35.168.32	アメリカ合衆国
	192.241.219.38	アメリカ合衆国
"GET /actuator/health HTTP/1.1"
	192.241.234.126	アメリカ合衆国
"GET /owa/auth/logon.aspx?url=https%3a%2f%2f1%2fecp%2f HTTP/1.1"
	192.241.237.44	アメリカ合衆国
"GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1"
	156.96.117.185	アメリカ合衆国
```

> < option m >  
※ multiple arguments can be specified
```
$ python3 hpot.py -m sample_log/8_https_1208
make out in current directory as 8_https_1208_request
```
```
$ cat 8_https_1208_request
"GET / HTTP/1.1"%%%%10
"GET /actuator/health HTTP/1.1"%%%%1
"GET /console/ HTTP/1.1"%%%%1
"GET /?XDEBUG_SESSION_START=phpstorm HTTP/1.1"%%%%1
"GET /owa/auth/logon.aspx?url=https%3a%2f%2f1%2fecp%2f HTTP/1.1"%%%%1
"GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1"%%%%1
"GET /wp-content/plugins/wp-file-manager/readme.txt HTTP/1.1"%%%%1
"GET /index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=HelloThinkPHP21 HTTP/1.1"%%%%1
"GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1"%%%%1
"POST /Autodiscover/Autodiscover.xml HTTP/1.1"%%%%1
"POST /api/jsonws/invoke HTTP/1.1"%%%%1
"POST /autodiscover HTTP/1.1"%%%%2
"POST /mifs/.;/services/LogService HTTP/1.1"%%%%1
"POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1"%%%%1
```

> < option i >  
※ multiple arguments can be specified
```
$ python3 hpot.py -i 8_https_1208_request 7_https_1208_request
make out in current directory as https_integrate_request
```
```
$ cat https_integrate_request
"GET / HTTP/1.0"%%%%2
"GET / HTTP/1.1"%%%%19
"GET /actuator/health HTTP/1.1"%%%%2
"GET /console/ HTTP/1.1"%%%%2
"GET /?XDEBUG_SESSION_START=phpstorm HTTP/1.1"%%%%2
"GET /owa/auth/logon.aspx?url=https%3a%2f%2f1%2fecp%2f HTTP/1.1"%%%%2
"GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1"%%%%2
"GET /wp-content/plugins/wp-file-manager/readme.txt HTTP/1.1"%%%%2
"GET /index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=HelloThinkPHP21 HTTP/1.1"%%%%2
"GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1"%%%%2
"POST /Autodiscover/Autodiscover.xml HTTP/1.1"%%%%2
"POST /api/jsonws/invoke HTTP/1.1"%%%%2
"POST /autodiscover HTTP/1.1"%%%%2
"POST /mifs/.;/services/LogService HTTP/1.1"%%%%2
"POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1"%%%%2
```

> < option d >
```
$ python3 hpot.py -d 8_http_1208_request 8_https_1208_request
make out in current directory as diff
8_https_1208_request - 8_http_1208_request = diff
```
```
$ cat diff
"GET /?XDEBUG_SESSION_START=phpstorm HTTP/1.1"
"GET /owa/auth/logon.aspx?url=https%3a%2f%2f1%2fecp%2f HTTP/1.1"
"GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1"
"GET /wp-content/plugins/wp-file-manager/readme.txt HTTP/1.1"
"GET /index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=HelloThinkPHP21 HTTP/1.1"
"GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1"
"POST /Autodiscover/Autodiscover.xml HTTP/1.1"
"POST /autodiscover HTTP/1.1"
"POST /mifs/.;/services/LogService HTTP/1.1"
"POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1"
```

***- parse pcapfile***
> < option p >
```
$ python3 hpot.py -p sample_log/8_https_1208.pcap

164.68.112.178	1  1
128.14.152.46	1  0
128.14.133.58	1  1
192.241.238.207	2  1
185.94.189.182	1  0
47.241.66.187	1  0
216.243.31.2	1  0
205.185.119.203	1  1
205.185.122.97	1  0
146.88.240.4	1  0
146.88.240.12	1  1
45.146.164.211	2  0
79.124.62.55	1  0
172.105.89.161	2  0
35.232.145.68	1  0
173.230.152.228	1  0
192.241.234.126	2  1
95.214.11.231	2  2
185.234.219.205	2  1
173.249.29.156	1  0
195.62.46.195	1  0
80.94.93.25	3  0
80.94.93.51	1  0
91.241.19.84	9  9
67.205.149.169	1  0
128.1.91.202	1  0
128.14.134.134	1  1
184.105.139.123	1  0
184.105.139.67	14  14
14.128.63.157	1  0
71.6.232.7	2  1
138.246.253.24	1  0
192.35.168.20	1  0
192.35.168.16	1  1
193.118.55.147	1  0
193.118.55.146	1  1
192.35.168.43	1  0
192.35.168.32	1  1
83.97.20.94	1  0
87.251.75.145	1  0
192.241.219.38	2  1
35.232.153.15	1  0
192.241.237.44	2  1
92.222.221.49	1  1
156.96.117.185	1  1
51.210.242.54	1  0

Access: 78	TLS_Access: 41
####################
0-1:	1
1-2:	5
2-3:	4
3-4:	1
4-5:	3
5-6:	1
6-7:	1
7-8:	3
8-9:	8
9-10:	10
10-11:	2
11-12:	16
12-13:	0
13-14:	0
14-15:	2
15-16:	3
16-17:	1
17-18:	3
18-19:	2
19-20:	3
20-21:	0
21-22:	6
22-23:	1
23-24:	2
####################
アメリカ合衆国: 25
イギリス: 3
シンガポール: 2
ドイツ連邦共和国: 7
フランス共和国: 3
ブルガリア共和国: 1
ポーランド共和国: 1
リトアニア共和国: 1
ルーマニア: 1
ロシア: 2
####################
make out in current directory as pcapch.txt
```
```
$ cat pcapch.txt
No.1 164.68.112.178(53052)  [2020-12-08 00:27:27]
> SYN
  SYN ACK
> ACK
> PSH ACK  ### ClientHello (TLSv1.1) ###
  ACK
  ACK  ### Server_Hello ###
  PSH ACK  ### Certificate ###
> ACK
  PSH ACK  ### Server_Key_Exchange Server_Hello_Done ###
> ACK
> FIN ACK
  FIN ACK
> FIN ACK

No.14 128.14.152.46(24947)  [2020-12-08 01:08:41]
> SYN
  SYN ACK
> RST
> RST

No.18 128.14.133.58(34522)  [2020-12-08 01:09:05]
> SYN
  SYN ACK
> ACK
> PSH ACK  ### ClientHello (TLSv1.2) ###
  ACK
  PSH ACK  ### Server_Hello Certificate Server_Key_Exchange Server_Hello_Done ###
> ACK
> PSH ACK  ### Client_Key_Exchange Change_Cipher_Spec Encrypted_Handshake_Message ###
  PSH ACK  ### Change_Cipher_Spec Encrypted_Handshake_Message ###
> ACK
> PSH ACK  ### Application_Data ###
  PSH ACK  ### Application_Data ###
  FIN PSH ACK  ### Application_Data ###
> ACK
> ACK
> PSH ACK  ### Alert ###
  RST
> FIN ACK
  RST
```

> < option cpp >  
※ multiple arguments can be specified
```
$ python3 hpot.py -cpp sample_log/8_https_1208.pcap
Input Country:アメリカ合衆国
sample_log/8_https_1208.pcap  :  43
####################
0-1:	0
1-2:	4
2-3:	3
3-4:	1
4-5:	1
5-6:	0
6-7:	1
7-8:	3
8-9:	0
9-10:	1
10-11:	2
11-12:	15
12-13:	0
13-14:	0
14-15:	1
15-16:	2
16-17:	1
17-18:	0
18-19:	2
19-20:	0
20-21:	0
21-22:	5
22-23:	0
23-24:	1
####################
43
```

> < option cppp >  
※ multiple arguments can be specified
```
$ python3 hpot.py -cppp sample_log/8_https_1208.pcap
Input Country:アメリカ合衆国
"128.14.152.46" "128.14.133.58" "192.241.238.207" "216.243.31.2" "205.185.119.203" "205.185.122.97" "146.88.240.4" "146.88.240.12" "35.232.145.68" "173.230.152.228" "192.241.234.126" "67.205.149.169" "128.1.91.202" "128.14.134.134" "184.105.139.123" "184.105.139.67" "71.6.232.7" "192.35.168.20" "192.35.168.16" "192.35.168.43" "192.35.168.32" "192.241.219.38" "35.232.153.15" "192.241.237.44" "156.96.117.185"
```
