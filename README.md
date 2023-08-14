# DoS_Port_Filtering
A Lightweight DoS Detection and Mitigation Method Based on Port Filtering for IoT Device

# Program Structure
The program consists of one Python file **main.py**

# Usage
```
usage: main.py [-h] [-b BLACKLIST] [-t TIMEOUT] [-c CONFIG]

optional arguments:
  -h, --help            show this help message and exit
  -b BLACKLIST, --blacklist BLACKLIST
                        Blacklist File
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout
  -c CONFIG, --config CONFIG
                        Config File
```
The default value of timeout is 180 seconds and the default configuration file path is `/etc/blacklist.json`

# Requirements

**iptables** is required to execute firewall rules.
Python3 packages **pcapy, time, warnings, socket, struct, os, iptc, json, argparse** is required
