This is lua script calculates the Shannon Entropy of given domains and returns a true or a false based on whether or not they exceed a specified threshhold, which triggers an alert on the Suricata rule.

Included is a dummy suricata config YAML that will allow this script to execute.

Additionally, the following rules are in the local.rules file:

- a check for PNG files based on the byte header
- a check for Base64 encoding based on the format
- a simple check for possible nmap -sS scans using a timing threhshold
