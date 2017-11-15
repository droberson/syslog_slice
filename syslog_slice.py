#!/usr/bin/env python

"""
syslog_slice.py -- by Daniel Roberson @dmfroberson October/2017

TODO:
  - implement cli flags outlined in argparse
  - color
  - resolve hosts
  - log file
  - ipv6
  - MAC addresses?
  - keyword searching
  - sqlite3 logging
  - daemonize
  - collect X minutes of traffic before exiting
  - collect N entries before exiting
"""

import re
import os
import time
import socket
import struct
import argparse
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * # pylint: disable=unused-import,unused-wildcard-import,wildcard-import


class Settings(object):
    """ Settings Object -- Stores various application settings and the
                        -- methods to update, retrieve, and manipulate them
    """
    __config = {
        "inverse" : False,
        "severity" : None,
        "facility" : None,
        "logfile" : "syslog_slice.log",
        "numentries" : 0,
        "minutes" : 0,
        "daemonize" : False,
    }

    __settings = [
        "inverse",
        "severity",
        "facility",
        "logfile",
        "numentries",
        "minutes",
        "daemonize",
    ]

    src_addresses = []
    dst_addresses = []

    @staticmethod
    def get(name):
        """ Settings.get() -- Retrieve a configuration setting.

        Args:
            name (str) - Name of setting to retrieve.

        Returns:
            Contents of configuration setting.
        """
        return Settings.__config[name]


    @staticmethod
    def set(name, value):
        """ Settings.set() -- Apply a configuration setting.

        Args:
            name (str) - Name of configuration setting.
            value      - Value to apply to setting.

        Returns:
            Nothing.

        Raises a NameError exception if the supplied setting does not exist.
        """
        if name in Settings.__settings:
            Settings.__config[name] = value
        else:
            raise NameError("Not a valid setting for set() method: %s" * name)


    @staticmethod
    def add_source(source):
        """ Settings.add_source() -- Add a source address or network to filter
                                  -- list.

        Args:
            source (str) - IP address or network in CIDR notation.

        Returns:
            Nothing.
        """
        if "/" not in source:
            # Use /32 to match specific IP address
            source += "/32"

        if source.count("/") > 1:
            print "[-] Invalid source address: %s" % source
            print "[-] Exiting."
            exit(os.EX_USAGE)

        address, mask = source.split("/")

        # Make sure CIDR notation is right.
        if int(mask) > 32 or int(mask) < 0:
            print "[-] Invalid CIDR mask: %s" % mask
            print "[-] Exiting."
            exit(os.EX_USAGE)

        # Validate IP address
        try:
            socket.inet_aton(address)
        except socket.error:
            print "[-] Invalid source IP address: %s" % address
            print "[-] Exiting."
            exit(os.EX_USAGE)

        # Add network to array
        Settings.src_addresses.append(
            ip_to_long(address) & build_netmask(int(mask))
        )


    @staticmethod
    def add_destination(destination):
        """ Settings.add_destination -- Add a destination address or network to
                                     -- filter list.
        Args:
            source (str) - IP address or network in CIDR notation.

        Returns:
            Nothing.
        """
        if "/" not in destination:
            # Use /32 to match specific IP address
            destination += "/32"

        if destination.count("/") > 1:
            print "[-] Invalid destination address: %s" % destination
            print "[-] Exiting."
            exit(os.EX_USAGE)

        address, mask = destination.split("/")

        # Get right or get left.
        if int(mask) > 32 or int(mask) < 0:
            print "[-] Invalid CIDR mask: %s" % mask
            print "[-] Exiting."
            exit(os.EX_USAGE)

        # Validate IP address
        try:
            socket.inet_aton(address)
        except socket.error:
            print "[-] Invalid destination IP address: %s" % address
            print "[-] Exiting."
            exit(os.EX_USAGE)

        # Add network to array
        Settings.dst_addresses.append(
            ip_to_long(address) & build_netmask(int(mask))
        )


def ip_to_long(address):
    """ ip_to_long() -- Convert IP address to unsigned long.

    Args:
        address(str) - IP address. Ex: "127.0.0.1".

    Returns:
        IP address represented as a long.
    """
    return struct.unpack("!L", socket.inet_aton(address))[0]


def build_netmask(bits):
    if bits == 0:
        return 0

    return (2L << bits - 1) - 1


def get_syslog_severity(severity):
    """ get_syslog_severity() -- Get human-readable syslog severity name

    Args (required):
        severity (int) - Severity number.

    Returns:
        Name of severity upon success.
        "UNKNOWN" on failure.
    """
    severities = (
        (0, "EMERGENCY"),
        (1, "ALERT"),
        (2, "CRITICAL"),
        (3, "ERROR"),
        (4, "WARNING"),
        (5, "NOTICE"),
        (6, "INFO"),
        (7, "DEBUG")
    )

    try:
        return severities[severity][1]
    except (IndexError, TypeError):
        return "UNKNOWN"


def get_syslog_facility(facility):
    """ get_syslog_facility() -- Get human-readable syslog facility name.

    Args (required):
        facility (int) - Facility number.

    Returns:
        Name of facility upon success.
        "UNKNOWN" on failure.
    """
    facilities = (
        (0, "KERNEL"),
        (1, "USER"),
        (2, "MAIL"),
        (3, "DAEMON"),
        (4, "AUTH"),
        (5, "SYSLOG"),
        (6, "LPR"),
        (7, "NEWS"),
        (8, "UUCP"),
        (9, "TIME"),
        (10, "AUTH"),
        (11, "FTP"),
        (12, "NTP"),
        (13, "AUDIT"),
        (14, "ALERT"),
        (15, "CLOCK"),
        (16, "LOCAL0"),
        (17, "LOCAL1"),
        (18, "LOCAL2"),
        (19, "LOCAL3"),
        (20, "LOCAL4"),
        (21, "LOCAL5"),
        (22, "LOCAL6"),
        (23, "LOCAL7"),
    )

    try:
        return facilities[facility][1]
    except (IndexError, TypeError):
        return "UNKNOWN"


def should_i_print_this(src, dst, severity, facility, message):
    """ should_i_print_this() -- Determine if a packet should be printed or not.

    Args:
        src (str)      - Source IP address.
        dst (str)      - Destination IP address. 
        severity (int) - Syslog facility.
        facility (int) - Syslog facility.
        message (str)  - Contents of syslog message.

    Returns:
        True if packet matches output criteria.
        False if packet does not match output criteria.
    """
    srcaddr = ip_to_long(src)
    dstaddr = ip_to_long(dst)

    # See if a matching source network exists
    srcmatch = False
    for network in Settings.src_addresses:
        if network & srcaddr == network:
            srcmatch = True
            break

    # See if a matching destination network exists
    dstmatch = False
    for network in Settings.dst_addresses:
        if network & dstaddr == network:
            dstmatch = True
            break

    # GET SOME
    result = srcmatch & dstmatch
    if Settings.get("inverse") is True:
        return not result
    return result



def parse_syslog(pkt):
    """ parse_syslog() -- Parse syslog packets passed from Scapy

    Args (required):
        pkt - Scapy packet object

    Returns:
        Nothing
    """
    try:
        payload = str(pkt[Raw].load).rstrip()
    except IndexError:
        return

    # Determine protocol (is there a better way for this?)
    protocol = "UNKNOWN"
    try:
        if pkt[IP].proto == 17:
            protocol = "UDP"

        if pkt[IP].proto == 6:
            protocol = "TCP"

        source_ip = pkt[IP].src
        dest_ip = pkt[IP].dst
    except IndexError:
        source_ip = "127.0.0.1"
        dest_ip = "127.0.0.1"

    # Determine if this is a syslog packet
    try:
        prival = int(re.search(r"\d+|$", payload).group())
        message = payload.partition("<" + str(prival) + ">")[2]
    except (ValueError, AttributeError):
        # Doesn't match <prival>message format. Probably not a syslog message.
        print("%s %s %s -> %s --- MALFORMED SYSLOG PACKET ---" %
              (time.time(),
               protocol,
               source_ip,
               dest_ip))
        return

    # Calulate facility and severity from prival
    severity = prival & 0x07
    facility = prival >> 3

    if should_i_print_this(source_ip, dest_ip, severity, facility, message):
        print("%s %s %s -> %s [%s] [%s]: %s" %
              (time.time(),
               protocol,
               source_ip,
               dest_ip,
               get_syslog_severity(severity),
               get_syslog_facility(facility),
               message))


def parse_cli():
    """ parse_cli() -- Parse CLI input using argparse

    Args:
        None

    Returns:
        ArgumentParser namespace relevant to supplied CLI options
    """
    description = \
        "example: ./syslog_slice.py -s 10.10.10.0/24 -e CRITICAL"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-s",
                        "--source",
                        required=False,
                        action="append",
                        help="Source IP address or CIDR network")
    parser.add_argument("-d",
                        "--destination",
                        required=False,
                        action="append",
                        help="Destination IP address or CIDR network")
    parser.add_argument("-e",
                        "--severity",
                        required=False,
                        help="Filter by severity. \"list\" shows options")
    parser.add_argument("-f",
                        "--facility",
                        required=False,
                        help="Filter by log level. \"list\" shows options")
    parser.add_argument("-i",
                        "--inverse",
                        required=False,
                        default=False,
                        action="store_true",
                        help="Reverse the logic provided (grep -v)")
    args = parser.parse_args()

    # Inverse setting
    Settings.set("inverse", args.inverse)

    # Add source networks
    try:
        for network in args.source:
            Settings.add_source(network)
    except TypeError:
        # No sources supplied, so match everything.
        Settings.add_source("0.0.0.0/0")

    # Add destination networks
    try:
        for network in args.destination:
            Settings.add_destination(network)
    except TypeError:
        # No destinations supplied, so match everything.
        Settings.add_destination("0.0.0.0/0")

    return args


if __name__ == "__main__":
    print "[+] syslog_slice.py -- by Daniel Roberson @dmfroberson"
    print ""

    args = parse_cli()

    # Start the sniffer..
    print "[+] Starting the sniffer."
    try:
        sniff(filter="port 514", prn=parse_syslog)
    except socket.error:
        print "[-] Unable to open socket. Are you root?"
        print "[-] Exiting."
        exit(os.EX_USAGE)

    # Not reached
    exit(os.EX_OK)
