"""
Script: image_cw.py
Description: Finds images in HTTP GET requests.
Author: James H
Modified: 28/11/2024
PEP8 Score: 9.44
================================================
This is the image file.
================================================
"""

import dpkt


def get_images(pcap):
    """
    Filter for HTTP requests only, searching for specifically GET.
    Store any found images in a list, image_results.
    """
    image_results = []

    for unused_ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip_ad = eth.data
            tcp = ip_ad.data

            # Find all HTTP requests
            http = dpkt.http.Request(tcp.data)
            if http.method == "GET":
                uri = http.uri.lower()

                # Checks to see if the uri contains any of the specified extensions
                if any(ext in uri for ext in [".gif", ".jpeg", ".jpg", ".png"]):

                    # Get the value of key host and add with uri to get workable link
                    head = http.headers.get("host")
                    full = f"http://{head}{uri}"
                    image_results.append(full)

        except Exception:
            # Need to pass here, errors that will be found aren't critical
            pass

    return image_results
