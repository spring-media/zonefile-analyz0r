# Zonefile validation

## Installation

* Pipenv https://pypi.org/project/pipenv/

```sh
brew install pipenv
```

### Execute

```sh
$ pipenv shell
$ pipenv install
$ python check.py

Usage: python check.py [FILE] [MY_DOMAIN]
    [FILE] zone file
    [MY_DOMAIN] treat this domain as 1st party
```

Output may look like this

```sh
$ python check.py zonefile_sample welt.de

[CNAME] Probably First Party:
www.welt.de -> welt.de.edgekey.net
HTTP  [301] -> https://www.welt.de/ [200]
HTTPS [200]

amp.welt.de -> amp.up.welt.de
HTTP  [301] -> https://amp.welt.de/ [404]
HTTPS [404]

[CNAME] Probably 3rd Party:
gutscheine.welt.de -> a.welt-gutscheine.de
HTTP  [301] -> https://gutscheine.welt.de/ [200]
HTTPS [200]

A records:
flatworld.welt.de
HTTP  [301] -> https://www.welt.de/politik/ausland/ [200]
HTTPS [ERR]
```
