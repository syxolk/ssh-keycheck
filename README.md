# ssh-keycheck

[![Build Status](https://travis-ci.org/syxolk/ssh-keycheck.svg?branch=master)](https://travis-ci.org/syxolk/ssh-keycheck)

`ssh-keycheck` is a tool that gives you a quick overview of all authorized
ssh keys on your server and their last use and usage count. This may be
helpful for manual key expiration.

This tool does not attempt to change anything. All files are opened in read-only
mode.

## Installation

Download the latest package from the releases page and unpack it.

## Usage

```
~$ sudo ssh-keycheck
USER  NAME              TYPE      LAST USE       COUNT  LAST IP
root  rsa-key-20170101  RSA-4096  never              -  -
root  rsa-key-20170102  ED25519   9 minutes ago      3  10.0.0.10
```

```
~$ sudo ssh-keycheck -fingerprint
USER  NAME              TYPE      LAST USE       COUNT  LAST IP    FINGERPRINT
root  rsa-key-20170101  RSA-4096  never              -  -          00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
root  rsa-key-20170102  ED25519   9 minutes ago      3  10.0.0.10  ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00
```

```
~$ sudo ssh-keycheck -csv
user,name,type,keylen,lastuse,count,lastip,fingerprint
root,rsa-key-20170101,RSA,4096,,0,,00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
root,rsa-key-20170102,ED25519,256,2017-08-22T19:45:32+02:00,3,10.0.0.10,ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00
```

## How does it work?
- Read all users from `/etc/passwd`
- Read `~/.ssh/authorized_keys` file from each user's home directory
- Read all `/var/log/auth.log*` files and search for *Accepted publickey*
- Match public keys to logs

You may need to change your `/etc/ssh/sshd_config` in order to enable the
required log messages:
```
LogLevel VERBOSE
```

## Why does it require root?
The log files under `/var/log` require root rights.

## Development
Requires a recent Go version (only tested with Go 1.8)

```
go get github.com/syxolk/ssh-keycheck
```
