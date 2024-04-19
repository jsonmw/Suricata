# This program loads an IP reputation list from a file and converts it into IPREP format
# for Suricata IDS. The reputation score is determined by frequency of appearance in the
# reputation CSV.

import csv
import os
import re

# Stores list in memory
reputation_dict = {}

# Specify attributes
input_file = 'mdl.csv'
output_file = "mdl.list"
ip_location = 2 # location of the IP field in the CSV file, i.e. "0,1,2,3"
category = "1" # the idea for this is if you wanted to extend later with multiple categories in categories.txt

# defines IPv4 regex
ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

# Open the input file for reading
with open(input_file, newline='', encoding='latin-1') as reputation_file:
    reader = csv.reader(reputation_file)
    for row in reader:
        if not row:
            continue  # Skips if empty

        # Extracts valid IPv4 addresses using regular expression
        ip_match = re.search(ip_pattern, row[ip_location])
        if ip_match:
            ip_address = ip_match.group()
        else:
            continue
        
        # Looks for IP address in dictionary, increments reputation score if found, to a 127 max
        if ip_address not in reputation_dict:
            reputation_dict[ip_address] = 2
        else:
           if reputation_dict[ip_address] < 127 :
                reputation_dict[ip_address] += 2

        if reputation_dict[ip_address] > 127 :
            reputation_dict[ip_address] = 127

# Delete the existing output file if it exists
if os.path.exists(output_file):
    os.remove(output_file)

# Sorts data and writes to file
with open(output_file, 'w') as file:
    for key in sorted(reputation_dict):
        file.write(f"{key},{category},{reputation_dict[key]}\n")