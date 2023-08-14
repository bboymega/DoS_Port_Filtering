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
BLACKLIST is the path to the pre-loaded blacklist file, TIMEOUT is the timeout of blacklist rules, and CONFIG is the path to the configuration file. All these arguments are optional.

The default value of TIMEOUT is 180 seconds.

# Requirements

**iptables** is required to execute firewall rules.
Python3 packages **pcapy, time, warnings, socket, struct, os, iptc, json, argparse** is required

# Configuration File

The configuration file is formatted and parsed in JSON structure. Here is an example of the configuration file.
```
{
   "blacklist": "/etc/blacklist.json", //Path to the pre-loaded blacklist file
   "timeout": 180 //timeout of blacklist rules
}
```
