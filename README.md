# ssh-keycheck

`ssh-keycheck` is a tool that gives you a quick overview over all authorized
ssh keys on your server and their last usage.

## Installation

Download the latest package from the releases page and unpack it.

## Usage

```
~$ sudo ssh-keycheck
USER  NAME              ALG          USAGE          FINGERPRINT
root  rsa-key-20170101  ssh-rsa      never          00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
root  rsa-key-20170102  ssh-ed25519  9 minutes ago  ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00
```

## How does it work?
- Read all users from `/etc/passwd`
- Read `~/.ssh/authorized_keys` file from each user's home directory
- Read all `/var/log/auth.log*` files and search for *Accepted publickey*
- Match public keys to logs

## Why does it require root?
The log files under `/var/log` require root rights.

## Development
Requires a recent Go version (only tested with Go 1.8)

```
go build
```
