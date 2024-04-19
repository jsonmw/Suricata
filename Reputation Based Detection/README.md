This is designed to automatically update based on the malware domain list csv file one could curl from the internet.

A bash script that can be used in a cron job wraps a simple python program that extracts the IPs from the CSV using a regex, and then populates them into a list that is readable by suricata and able to be added to a rule.

Included is a dummy suricata config YAML and categories.txt that will allow this script to execute, and for the mdl.list that is produced to be used as the iprep for reputation checking.
