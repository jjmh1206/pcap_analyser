"""
Script: kml_cw.py
Description: Creates a KML file based on the destination addresses
found in a pcap.
Author: James Hunter, 40646575
Modified: 30/11/2024
Pylint Score: 9.46
================================================
This is the KML file of the coursework.
Code in Lab 9 was reused here, the variable names are mostly the same.
================================================
"""

import socket
import geoip2.database
import dpkt
import simplekml


def dest_addr(pcap) -> set:
    """
    Collect destination IPs and add them to a set.
    Information is taken from pcap.
    """
    ip_dest = set()
    for unused_ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            if isinstance(ip, dpkt.ip.IP):
                dst = socket.inet_ntoa(ip.dst)
                ip_dest.add(dst)

        except Exception:
            # Need to pass here, errors that will be found aren't critical
            continue

    return ip_dest


def geolocate(ip_dest: set, geo_path: str) -> list:
    """
    Takes the created set of addresses and uses the geodb file
    to match the IP to the location.
    Creates dictionaries for each IP and is put into a list for
    later use.
    """
    geo_data = []
    with geoip2.database.Reader(geo_path) as reader:
        for ip in ip_dest:
            try:
                # Take data from reader and append to the list using geo import
                data = reader.city(ip)
                geo_data.append({
                    "ip": ip,
                    "city": data.city.name or "City not found",
                    "country": data.country.name or "Country not found",
                    "latitude": data.location.latitude,
                    "longitude": data.location.longitude
                })

            except Exception:
                # Just passing here again because there are alot of errors
                # Using geo errors like AddressNotFound clutters the output
                continue

    return geo_data


def create_kml(geo_data: list, output_kml: str) -> None:
    """
    Finally begin using all collected data to build the kml file.
    Iterates through the geo list and uses keys to add values to new data.
    """
    kml = simplekml.Kml()

    # Iterate through the list for dict values if they are there
    for add in geo_data:
        if add["latitude"] is not None and add["longitude"] is not None:

            # Create a newpoint and add data using the keys
            kml.newpoint(
                name = add["ip"],
                description = f"Location: {add['city']}, {add['country']}",
                coords = [(add["longitude"], add["latitude"])]
            )

    # Save kml as output_kml
    kml.save(output_kml)
    print(f"(!) KML file created, data has been sent to {output_kml}.")


def get_kml(pcap, geodb_path: str, output_file: str) -> None:
    """
    This is the calling function that is used in the main file.
    Data from the other functions is saved here and printed in main script.
    """
    dest_ips = dest_addr(pcap)
    geolocated_data = geolocate(dest_ips, geodb_path)
    create_kml(geolocated_data, output_file)
