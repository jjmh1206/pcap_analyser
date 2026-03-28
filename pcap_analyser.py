"""
Script: pcap_analyser.py
Description: Analyses pcap files and sorts IP data into a readable table.
Author: James Hunter, 40646575
Modified: 17/11/2024
Pylint Score: 9.84
================================================
This is the main file of the coursework.
Use this file only for running the program, the code to run the files on
their own was removed after testing. This program will not work with
pcapng extension, use pcap only.
================================================
"""

import sys
import dpkt

# My other scripts
import image_cw
import email_cw
import summary_cw
import kml_cw


def read_pcap(file_pcap: str) -> None:
    """
    Main function that is called from the boiler.
    Calls functions from imported scripts.
    """
    try:
        with open(file_pcap, "rb") as open_pcap:

            print("[!!!] File read successfully...")


            def file_reset(file):
                """
                Nested function used for resetting the file position after
                each imported function call.
                This prevents there being no data left to read, resulting
                in empty tables, etc.
                """
                file.seek(0)
                return dpkt.pcap.Reader(file)


            pcap = dpkt.pcap.Reader(open_pcap)

            # Call email_cw function, print found emails
            emails = email_cw.get_email(pcap)
            if emails['To'] or emails['From'] or emails['Other']:
                print(f"\n[!!!] Emails in {file_pcap}:")

                # Print seperately each key value (email) if it exists
                if emails['From']:
                    print("(!) From addresses:")
                    for email in emails['From']:
                        print(email)

                if emails['To']:
                    print("(!) To addresses:")
                    for email in emails['To']:
                        print(email)

                if emails['Other']:
                    print("(!) Other addresses:")
                    for email in emails['Other']:
                        print(email)

                pcap = file_reset(open_pcap)

            else:
                print("[!!!] There were no emails in this file...")

            # Call image_cw function, print found image
            images = image_cw.get_images(pcap)
            if images:
                num = 0
                print(f"\n[!!!] Images in {file_pcap}:")
                for image in images:
                    num += 1
                    print(f"({num}) {image}")

                pcap = file_reset(open_pcap)

            else:
                print("[!!!] There were no images in this file...")

            # Call summary_cw function, print table
            summaries = summary_cw.get_summary(pcap)
            if summaries:
                num = 0
                print(f"\n[!!!] Protocols in {file_pcap}:")
                print("PROTOCOL - COUNT - FT - LT")

                for summary in summaries:
                    num += 1
                    print(f"({num}) {summary}")

                pcap = file_reset(open_pcap)

            else:
                print("[!!!] There were no protocols in this file...")

            # Call kml_cw function, create kml file
            geo_file = "GeoLite2-City_20190129.mmdb"
            kml_output = "output.kml"
            print("\n[!!!] Attempting to create KML...")
            kml_cw.get_kml(pcap, geo_file, kml_output)
            print(f"(!) Check current directory for {kml_output}.")

    # Exception block built based on errors produced while writing
    except FileNotFoundError as e:
        print(f"The file {file_pcap} cannot be found. Check the path and try again. \n{e}",
              file=sys.stderr)
    except UnicodeDecodeError as e:
        print(f"The file {file_pcap} cannot be decoded using the current format. \n{e}",
              file=sys.stderr)


# Standard boiler to call functions
if __name__ == "__main__":
    input_file = input("Enter the pcap filename: ")
    print(f"[!!!] Attempting to run file {input_file}...")
    read_pcap(input_file)
