"""
Script: email_cw.py
Description: Finds unique email addresses in a pcap file.
Author: James Hunter, 40646575
Modified: 25/11/2024
Pylint Score: 10.00
================================================
This is the email file of the coursework.
Code in Lab 7b and 7c was reused here, the variable names are mostly the same.
================================================
"""

import sys
import re
import dpkt


def get_email(pcap):
    """
    Create a dictionary containing email values in the to and from
    fields. Include other to consider emails that exist outside of
    those fields.
    """
    # Create dictionary with unique key values
    email_addr = {'To': set(), 'From': set(), 'Other': set()}

    try:
        for unused_ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Function call inside the loop to iterate values to the dict
            # Same layer 3 check as before, only looking for IP packets
            if isinstance(ip, dpkt.ip.IP):
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    email_data(tcp, email_addr)

    except UnicodeDecodeError as e:
        print(f"The file cannot be decoded using the current format. \n{e}",
              file=sys.stderr)

    return email_addr


def email_data(tcp_data, email_addr):
    """
    Take the data in get_email, decode it, and use regex for finding
    emails in the to or from fields, if they aren't in those, then
    add to the other category.
    """
    try:
        # Needs a decode here otherwise it will produce errors
        decode_data = tcp_data.data.decode(errors="ignore")

        # Regex for the to and from fields
        from_regex = r'FROM:\s*<?(\w+[\.-]?\w*@\w+\.\w+\.?\w*)>?'
        to_regex = r'TO:\s*<?(\w+[\.-]?\w*@\w+\.\w+\.?\w*)>?'

        # Use re with regex pattern to search the decode data for from
        from_matches = re.findall(from_regex, decode_data)
        email_addr['From'].update(from_matches)

        # Use re with regex pattern to search the decode data for to
        to_matches = re.findall(to_regex, decode_data)
        email_addr['To'].update(to_matches)

        # Other regex for addresses not in to or from
        other_regex = r'\w+[\.-]?\w*@\w+\.\w+\.?\w*'
        other_matches = re.findall(other_regex, decode_data)

        # Addresses that aren't in to or from are added to other
        for email in other_matches:
            if email not in email_addr['To'] and email not in email_addr['From']:
                email_addr['Other'].add(email)

    except UnicodeDecodeError as e:
        print(f"The file cannot be decoded using the current format. \n{e}",
              file=sys.stderr)
