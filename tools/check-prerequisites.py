#!/usr/bin/python3
import sys
import argparse
import ipaddress
import yaml

BACKEND_NAME = "backends"
RELAY_NAME = "relays"
GOPHISH_NAME = "backends_gophish"
EVILGINX2_NAME = "relays_evilginx2"
PHISHING_NAME = "relays_phishing"
NGINX_NAME = "relays_nginx"
OSINT_NAME = "backends_osint"
COBALTSTRIKE_NAME = "backends_cobalt_strike"


class BColors:
    """
    Some nicely formatted console colors
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def parse_yaml(filename):
    """
    Safely load ad YAML file from disk
    """
    with open(filename, 'r') as stream:
        return yaml.safe_load(stream)


def print_deployment_node_prerequisite(ip_space):
    """
    Print some important node requirements
    """
    print(BColors.OKCYAN + "\nDeployment node Requirements:" + BColors.ENDC)
    print("This node that will deploy the infrastructure must be located in one of the following networks")
    print("Otherwise installation will fail because you will be locked out after server hardening")
    for network in ip_space:
        print(BColors.WARNING + '- ' + network + BColors.ENDC)


def print_basic_prerequisites(systems, ansible_user):
    """
    Print the basic requirements
    """
    print(BColors.OKCYAN + "\nBasic Requirements:" + BColors.ENDC)
    print("- Running Ubuntu 20.04")
    print("- You have connected via SSH with the user " + ansible_user + " (so no more host verification etc)")
    print("- The SSH key for the account is unlocked")
    print("This concerns the following systems:")
    for host in systems[BACKEND_NAME]["hosts"]:
        print(BColors.WARNING + "- ssh " + ansible_user + "@" + systems[BACKEND_NAME]["hosts"][host]["ansible_host"] + BColors.ENDC)
    for host in systems[RELAY_NAME]["hosts"]:
        print(BColors.WARNING + "- ssh " + ansible_user + "@" + systems[RELAY_NAME]["hosts"][host]["ansible_host"] + BColors.ENDC)


def print_c2_prerequisites(systems, c2_address_space):
    """
    Print requirements for the C2
    """
    print(BColors.OKCYAN + "\nC2 Requirements:" + BColors.ENDC)
    print("- All backend systems must be located in the C2 network as defined in the config file")
    print("- If systems do not comply with this they will be listed below")
    for host in systems[BACKEND_NAME]["hosts"]:
        host_ip = ipaddress.ip_address(systems[BACKEND_NAME]["hosts"][host]["ansible_host"])
        host_is_in_address_space = False
        for network in c2_address_space:
            net = ipaddress.ip_network(network)
            if host_ip in net:
                host_is_in_address_space = True
        if not host_is_in_address_space:
            print(BColors.FAIL + "- " + str(host_ip) + " is not in C2 IP Space)" + BColors.ENDC)


def print_nginx_prerequisites(systems):
    """
    Print requirements for an Nginx host
    """
    print(BColors.OKCYAN + "\nNginx Requirements:" + BColors.ENDC)
    print("- The A record of the domain must point to the correct server")
    print("- Make sure it already resolves correctly")
    print("- For phishing consider using domains older than 7 days")
    print("This concerns the following domains:")
    for host in systems[NGINX_NAME]["hosts"]:
        domain = systems[NGINX_NAME]["hosts"][host]['domain_name']
        address = systems[NGINX_NAME]["hosts"][host]['ansible_host']
        print(BColors.WARNING + "- " + domain + " points to " + address + BColors.ENDC)


def print_phishing_prerequisites(systems):
    """
    Print requirements for a GoPhish host
    """
    print(BColors.OKCYAN + "\nPhishing Requirements:" + BColors.ENDC)
    print("- The A record of the domain must point to the correct server")
    print("- Make sure it already resolves correctly")
    print("- Consider using domains older than 7 days")
    print("This concerns the following domains:")
    for host in systems[PHISHING_NAME]["hosts"]:
        domain = systems[PHISHING_NAME]["hosts"][host]['domain_name']
        address = systems[PHISHING_NAME]["hosts"][host]['ansible_host']
        print(BColors.WARNING + "- " + domain + " points to " + address + BColors.ENDC)

def main():
    """
    Start of the prerequisites check
    """
    parser = argparse.ArgumentParser(
        description="Creates a set of prerequisites for deploying the Red Teaming infrastructure")

    parser.add_argument('directory', help="Provide the path to the config directory")
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    hosts_yaml = parse_yaml(options.directory + "/hosts.yml")
    config_yaml = parse_yaml(options.directory + "/configuration.yml")
    c2_address_space = config_yaml["company_c2_space"]
    ansible_user = config_yaml["ansible_user"]
    company_ip_space = config_yaml["company_ip_space"]

    print_deployment_node_prerequisite(company_ip_space)
    print_basic_prerequisites(hosts_yaml, ansible_user)
    if BACKEND_NAME in hosts_yaml:
        print_c2_prerequisites(hosts_yaml, c2_address_space)
    if NGINX_NAME in hosts_yaml:
        print_nginx_prerequisites(hosts_yaml)
    if EVILGINX2_NAME in hosts_yaml:
        print_evilnginx2_prerequisites(hosts_yaml)
    if PHISHING_NAME in hosts_yaml:
        print_phishing_prerequisites(hosts_yaml)


if __name__ == '__main__':
    main()
