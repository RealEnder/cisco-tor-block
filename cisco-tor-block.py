#!/usr/bin/env python
"""
cisco-tor-block, Pull TOR exit nodes and push them as cisco router access list
Copyright (C) 2015  Alex Stanev, alex at stanev dot org

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import urllib2
import re
import socket
import struct
from zlib import adler32
from Exscript.protocols import SSH2
from Exscript import Account


# Configuration
config = {
    "cisco": {
        "host": "",  # cisco router host
        "user": "",  # username
        "pass": ""   # password
    },
    "ssh": {
        "logfile": None,       # file to log comm or None
        "connect_timeout": 60  # timeout in seconds
    },
    "whitelist": [],                                          # whitelist networks in net/mask format, eg. 127.0.0.1/8
    "ea_url": "https://check.torproject.org/exit-addresses",  # "official" exit nodes service
    "ea_file": "exit-addresses.txt"                           # reslut from check, must be writable
}

VER = "0.1"


class CiscoTorBlock():
    """ Main class """

    conf = None
    ea_list = None

    def __init__(self, c=None):
        self.conf = c

    def run(self):
        """ Main routine """
        self.get_ea(self.conf["ea_url"])
        iplist = self.parse_ea_list()
        self.push_cisco(iplist)
        self.write_ea()

    def get_ea(self, url):
        """ Download exit nodes, check if there are changes """

        print "Pulling current TOR exit nodes..."

        try:
            response = urllib2.urlopen(url)
        except urllib2.HTTPError:
            print "TORcheck unavailable"
            exit(1)
        except Exception as e:
            print "Exception: %s" % e
            exit(1)

        self.ea_list = response.read()
        response.close()

        ea_file_adler32 = 0
        if os.path.exists(self.conf["ea_file"]):
            try:
                with open(self.conf["ea_file"], "r") as f:
                    ea_file_adler32 = adler32(f.read())
            except Exception as e:
                print "Exception: %s" % e
                exit(1)

        if ea_file_adler32 == adler32(self.ea_list):
            print "Exit address list not changed, exiting"
            exit(0)

        print "TOR exit node list downloaded"

    def write_ea(self):
        try:
            f = open(self.conf["ea_file"], "w")
            f.write(self.ea_list)
            f.close()
        except Exception as e:
            print "Exception: %s" % e
            exit(1)

    def addressInNetwork(self, ip, net_n_bits):
        """ Does IP belongs to network """

        ipaddr = struct.unpack("<L", socket.inet_aton(ip))[0]
        net, bits = net_n_bits.split("/")
        netaddr = struct.unpack("<L", socket.inet_aton(net))[0]
        netmask = ((1L << int(bits)) - 1)

        return ipaddr & netmask == netaddr & netmask

    def parse_ea_list(self):
        """ Dumb regexp IP extractor and cleaner """

        # Extract all IP addresses
        ipPattern = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        findIP = re.findall(ipPattern, self.ea_list)
        findIP = set(findIP)

        # Clean all private and broadcast addresses, whitelists
        for ip in findIP:
            if not self.public_ipaddr(ip):
                findIP.remove(ip)
                continue
            for net in self.conf["whitelist"]:
                if self.addressInNetwork(ip, net):
                    findIP.remove(ip)
                    continue

        print "TOR exit list parsed: %d usable nodes" % len(findIP)

        return findIP

    def parse_cisco_list(self, cisco_list, torlist):
        """ Parese and split lists """

        def diff(a, b):
            """ Set diff """
            b = set(b)
            return [aa for aa in a if aa not in b]

        # extract all IP addresses
        ipPattern = re.compile("(\d+) permit ip host (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) any")
        findIP = re.findall(ipPattern, cisco_list)
        rulesLen = len(findIP)
        print "Rules found: %d" % rulesLen

        pair = dict()
        spair = set()
        for p in findIP:
            pair[p[1]] = p[0]
            spair.add(p[1])

        todel = set(diff(spair, torlist))
        toadd = set(diff(torlist, spair))
        todelno = set()
        for todelip in todel:
            todelno.add(pair[todelip])

        print "Rules to add: %d\nRules to remove: %d" % (len(toadd), len(todelno))

        # Check if we have to remove more than 40% of rules
        if rulesLen != 0:
            if len(todelno) / rulesLen * 1.0 > 0.4:
                print "Too many rules to remove! Check the exit node list URL."
                exit(1)

        return toadd, todelno

    def public_ipaddr(self, ip):
        """
        Validate public addressable IP address (not private, loopback, or broadcast)
        Shamelessly taken from https://github.com/vab/torblock , with fixes
        """

        quads = ip.split(".")
        # Invalid
        if (int(quads[0]) == 0):
            return False
        # Loop back
        elif (int(quads[0]) == 127):
            return False
        # Broadcast
        elif(int(quads[0]) == 255):
            return False
        # Private
        elif(int(quads[0]) == 10):
            return False
        elif((int(quads[0]) == 172) and ((int(quads[1]) > 15) and (int(quads[1]) < 32))):
            return False
        elif((int(quads[0]) == 192) and (int(quads[1]) == 168)):
            return False
        else:
            return True

    def push_cisco(self, iplist):
        """ Push rules to cisco router """

        # connect to device
        conn = SSH2(connect_timeout=self.conf["ssh"]["connect_timeout"], logfile=self.conf["ssh"]["logfile"])
        conn.set_driver("ios")

        print "Connecting to device..."
        try:
            conn.connect(self.conf["cisco"]["host"])
            conn.login(Account(name=self.conf["cisco"]["user"], password=self.conf["cisco"]["pass"]))
            conn.autoinit()

            print "Pulling current access list..."
            conn.execute("conf t")
            conn.execute("do show ip access-lists tor-block")

            toadd, todel = self.parse_cisco_list(conn.response, iplist)

            if len(toadd) == len(todel) == 0:
                print "No rule changes, exiting..."
                self.write_ea()
                exit(0)

            conn.execute("ip access-list extended tor-block")

            # add/remove new IPs to block
            print "Adding rules..."
            for ip in toadd:
                conn.execute("permit ip host " + ip + " any")

            print "Removing rules..."
            for no in todel:
                conn.execute("no " + no)

            conn.execute("end")

            print "Writing configuration..."
            conn.execute("wr")

            print "Closing connection"
            conn.send("exit\r")
            conn.close()
        except Exception as e:
            print "Exception: %s" % e
            exit(1)

# Execute
if __name__ == "__main__":
    print "cisco-tor-block v%s Copyright (C) 2015 Alex Stanev" % VER
    ctb = CiscoTorBlock(config)
    ctb.run()
