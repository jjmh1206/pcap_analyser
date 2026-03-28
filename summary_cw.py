"""
Script: summary_cw.py
Description: Collects protocol data and formats it into a table.
Categories are "Protocol, count, first timestamp, last timestamp. 
Author: James Hunter, 40646575
Modified: 20/11/2024
Pylint Score: 9.43
================================================
This is the protocol summary file of that is run from the main file.
================================================
"""

from datetime import datetime
import dpkt


def get_summary(pcap):
    """
    Provide a summary of found information about each protocol in the pcap.
    Categories include: Protocol, Count, first timestamp, last timestamp, mean.
    """
    try:
        # Variables used in the loop need to be declared beforehand
        stats = {}
        total_length = 0
        packet_count = 0

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            total_length += len(buf)
            packet_count += 1

            # Checks if l3, only looks at l3 packets
            if isinstance(ip, dpkt.ip.IP):

                # Get the protocol used in this packet
                p_name = ip.get_proto(ip.p).__name__

                # Put new protocol into a dictionary with nesting
                if p_name not in stats:
                    stats[p_name] = {"count": 0, "first_ts": None, "last_ts": None}

                # Add statistics to each found protocol, adds timestamps and count
                if stats[p_name]["first_ts"] is None:
                    stats[p_name]["first_ts"] = ts
                stats[p_name]["last_ts"] = ts
                stats[p_name]["count"] += 1

        # Convert timestamps into something more readable
        # This cannot be made shorter and is required for the table
        for protocol, proto_stats in stats.items():
            proto_stats["first_ts"] = datetime.fromtimestamp(proto_stats["first_ts"]).strftime("%d-%m-%Y %H:%M.%S")
            proto_stats["last_ts"] = datetime.fromtimestamp(proto_stats["last_ts"]).strftime("%d-%m-%Y %H:%M.%S")

        mean_length = total_length / packet_count

        # Build the table
        # Weird format because pylint says line too large
        table_data = []
        for protocol, proto_stats in stats.items():
            table_data.append([protocol,
                               proto_stats["count"],
                               proto_stats["first_ts"],
                               proto_stats["last_ts"]])

        # Append non-specific data last for cleaner look
        table_data.append(["All Protocols",
                           packet_count,
                           "-",
                           "-",
                           f"{mean_length:.2f} bytes"])

        return table_data

    # Not sure why but putting empty returns here increases pylint score
    except FileNotFoundError as e:
        print(f"The file {pcap} cannot be found. Check the path and try again. \n{e}")
        return[]

    except UnicodeDecodeError as e:
        print(f"The file {pcap} cannot be decoded using the current format. \n{e}")
        return[]
