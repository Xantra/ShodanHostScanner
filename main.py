"""
Script Name: main.py
Description: A script using an input CSV containing subdomains names that will lookup their IPs and use those IPs against the Shodan API to scan for open ports and vulnerabilities.
Author: Antoine Penin
Contact: apenin@deloitte.com
Version: 1.0
"""

# Modules
import csv
import shodan
import socket
import time
import pandas as pd
import sys
import getopt


def get_ip_address(domain_name, row_number):
    try:
        ip_address = socket.gethostbyname(domain_name)
        if ip_address:
            print("Row", row_number, "- IP Address for", domain_name, "is:", ip_address)
            return ip_address
        else:
            print("Row", row_number, "- Failed to retrieve IP address for", domain_name)
            return None
    except socket.gaierror:
        print("Row", row_number, "- Failed to retrieve IP address for", domain_name)
        return None


def main(argv):
    # Initialize variables for the mandatory arguments
    APIkey = None
    path = None

    # Define the available options and their flags
    long_options = ["APIkey=", "path=", "help", "version"]
    short_options = "k:p:hv"

    try:
        # Parse the command-line arguments
        opts, args = getopt.getopt(argv, short_options, long_options)
    except getopt.GetoptError:
        # Display an error message if the arguments are not valid
        print(
            "Usage: python test.py --APIkey <your Shodan APIkey> --path <path of the input file> [--help] [--version]")
        print(
            "Script Name: " + "main.py" + "\n" +
            "Description: " + "A script using an input CSV containing subdomains names that will lookup their IPs and use those IPs against the Shodan API to scan for open ports and vulnerabilities." + "\n" +
            "Author: " + "Antoine Penin" + "\n" +
            "Contact: " + "apenin@deloitte.com" + "\n" +
            "Version: " + "1.0"
        )

        sys.exit(2)

    # Process the parsed options
    for opt, arg in opts:
        if opt in ("-k", "--APIkey"):
            APIkey = arg
        elif opt in ("-p", "--path"):
            path = arg
        elif opt in ("-h", "--help"):
            print(
                "Usage: python test.py --APIkey <your Shodan APIkey> --path <path of the input file> [--help] [--version]")
            sys.exit()
        elif opt in ("-v", "--version"):
            print("Version 1.0")
            sys.exit()

    # Check if the mandatory arguments are provided
    if APIkey is None or path is None:
        print("APIkey and path are mandatory arguments.")
        print("Usage: python test.py --APIkey <APIkey> --path <path> [--help] [--version]")
        sys.exit(2)

    # Put data from input CSV into a DataFrame
    subdomains_data = pd.read_csv(path)

    # Create filenames
    current_time = int(time.time())
    filename_scan = 'scan_results_' + str(current_time) + '.csv'
    filename_ip = 'ip_addresses_' + str(current_time) + '.csv'

    # Create an empty list to store the IP addresses and subdomains, not duplicates of IP
    # This dictionary will be used with the Shodan API
    ip_addresses = {}

    # Create an empty dictionary to store the domain names and their corresponding IP addresses
    # Used to be saved as a CSV for reporting
    domain_ip_mapping = {}

    # Iterate over the domain names and get the IP addresses
    for i, domain in enumerate(subdomains_data['hostname'], 1):
        ip = get_ip_address(domain, i)
        if ip is not None:
            if domain not in domain_ip_mapping:
                domain_ip_mapping[domain] = ip
            if ip not in ip_addresses:
                ip_addresses[domain] = ip
        else:
            domain_ip_mapping[domain] = "Failed to retrieve an IP address for this subdomain"

    # Create a new DataFrame with the domain names and corresponding IP addresses
    df_ip_report = pd.DataFrame({'Domain Name': list(domain_ip_mapping.keys()),
                                 'IP Address': [domain_ip_mapping[domain] for domain in domain_ip_mapping]})

    # Save the DataFrame to a CSV file
    df_ip_report.to_csv(filename_ip, index=False)

    # Create a new DataFrame with the domain names and corresponding IP addresses for further use
    df_ip = pd.DataFrame({'Domain Name': list(domain_ip_mapping.keys()),
                          'IP Address': [domain_ip_mapping[domain] for domain in domain_ip_mapping]})
    # Initialize Shodan API
    api = shodan.Shodan(APIkey)

    # Perform the Shodan search
    # Iterate over the IP addresses
    for i, ip in enumerate(df_ip['IP Address'], 1):
        try:
            domain = df_ip.at[i - 1, 'Domain Name']  # Retrieve the domain name for the corresponding IP
            results = api.host(ip)
            ports = set()
            vulnerabilities = 0

            # Append the results to the existing CSV file
            with open(filename_scan, 'a', newline='') as csvfile:
                fieldnames = ['Domain', 'IP', 'Port', 'Banner', 'Vulnerability', 'Description', 'CVSS Score']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, escapechar='\\')

                # Check if the file is empty and write the header only once
                if csvfile.tell() == 0:
                    writer.writeheader()

                # Check if no ports are found
                if 'data' not in results or not results['data']:
                    writer.writerow({
                        'Domain': domain,  # Include the domain name in the row
                        'IP': ip,
                        'Port': 'N/A',
                        'Banner': 'N/A',
                        'Vulnerability': 'No ports found',
                        'Description': '',
                        'CVSS Score': ''
                    })
                else:
                    # Iterate over found ports and vulnerabilities
                    for item in results['data']:
                        port = item['port']
                        banner = item['data']
                        vuln_info = item.get('vulns', {})
                        ports.add(port)
                        if vuln_info:
                            vulnerabilities += len(vuln_info)
                        if not vuln_info:
                            writer.writerow({
                                'Domain': domain,  # Include the domain name in the row
                                'IP': ip,
                                'Port': port,
                                'Banner': banner,
                                'Vulnerability': 'No vulnerability found',
                                'Description': '',
                                'CVSS Score': ''
                            })
                        else:
                            for vuln_id, vuln_data in vuln_info.items():
                                vuln_desc = vuln_data.get('description', 'No description available')
                                cvss_score = vuln_data.get('cvss', '')
                                writer.writerow({
                                    'Domain': domain,  # Include the domain name in the row
                                    'IP': ip,
                                    'Port': port,
                                    'Banner': banner,
                                    'Vulnerability': vuln_id,
                                    'Description': vuln_desc,
                                    'CVSS Score': cvss_score
                                })

            print('Scan results saved to scan_results.csv - Row:', i)
            print('Ports found:', ', '.join(str(p) for p in ports))
            print('Number of vulnerabilities found:', vulnerabilities)
            print()  # Add an empty print statement for the newline

        except shodan.APIError as e:
            print('Error: %s - Row: %s' % (e, i))
            print()  # Add an empty print statement for the newline


if __name__ == "__main__":
    main(sys.argv[1:])
