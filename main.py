#!/usr/bin/python
# -*- coding: utf-8 -*-
import pyshark
import os
from tkinter import Tk, filedialog
from scapy.all import *
from collections import defaultdict, Counter

def pcap_to_dataframe(pcap_file):
    packets = rdpcap(pcap_file)  # Read the PCAP file
    # Extract relevant information from each packet
    data = []
    for packet in packets:
        if IP in packet:
            row = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Protocol': packet[IP].proto,
                'Length': len(packet),
                'Time': packet.time # others field required from protocol
            }
            data.append(row)

    # Convert the extracted data to a DataFrame
    df = pd.DataFrame(data)
    return df


def read_files_from_directory():
    root = Tk()
    root.withdraw()  # Hide the main window

    file_path = filedialog.askdirectory(title="Select file")

    if os.path.isfile(file_path) and (file_path.endswith(".pcap") or file_path.endswith(".pcapng") ) :
        try:
            capture = pcap_to_dataframe(file_path)
            # for packet in capture:            
            
                # if "IP" in packet:
                    # packet_number = packet.frame_info.number
                    # base_row = extract_base4(packet)
                # dst_ip=packet.ip.dst 
                # src_ip=packet.ip.src 
                # packet.

                # if hasattr(packet, 'eth'):
                    # eth_row = extract_eth(packet)
                # if hasattr(packet, 'vlan'):
                    # vlan_row = extract_vlan(packet)
                # if hasattr(packet, 'tcp'):
                    # tcp_row = extract_tcp(packet)
                # if hasattr(packet, 'udp'):
                            # field_names = packet.dns._all_fields
                            # print(field_names)
                    # udp_row = extract_udp(packet)       
        except Exception as e:
                print(f"Error processing file: {file_path}, Error: {str(e)}")
                traceback.print_exc()                    

  		return capture 
    else:
        print('invalid file or path')
        return None


def ospf_troubleshoot(capture):
  '''to become ospf running smoot, we need to check configuration of '''
  return

def bgp_troubleshoot(capture):
    '''to become bgp running smoot, we need to check '''
  return

def _troubleshoot(capture):
    '''to become bgp running smoot, we need to check '''
  return


def main()
# Read data from the selected directory path from the user
    df= read_files_from_directory()
    # pivot table and groupby before visualize the stat
    #get source ip and destination ip from user
    src_ip=input("Enter source ip/ ip range")
    dst_ip=input("Enter destination ip/ ip range")
    #get parameter at src ip and dst_ip end 

# Set the output directory for CSV files
    output_directory = os.path.join(file_path, "PCAP_Output")


if __name__ == "__main__":
    main()
