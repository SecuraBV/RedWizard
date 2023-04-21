#!/usr/bin/python3
import sys
import argparse
import yaml
from jinja2 import Environment

BACKEND_NAME = "backends"
RELAY_NAME = "relays"
GOPHISH_NAME = "backends_gophish"
OSINT_NAME = "backends_osint"
COBALTSTRIKE_NAME = "backends_cobalt_strike"

HOST_TEMPLATE = """
Host {{codename}}-{{name}}
HostName {{ip_address}}
{% for port in portforwards %}LocalForward {{port}} localhost:{{port}}
{% endfor %}
"""



def get_portforward(host_yaml, forward_var):
    """
    Create port forwarding variables based on the ansible configuration
    """
    ip_address = host_yaml["ansible_host"]
    portforward = host_yaml[forward_var]
    hostvars = {}
    hostvars["address"] = ip_address
    hostvars["forward"] = portforward
    return hostvars

def get_ip_address(host_yaml):
    """
    Get ip address of an ansible host
    """
    ip_address = host_yaml["ansible_host"]
    hostvars = {}
    hostvars["address"] = ip_address
    return hostvars

def add_to_forwards(host_vars, forward_port):
    """
    Add port forwards to the host variables
    """
    if "portforwards" not in host_vars:
        host_vars["portforwards"] = [forward_port]
    else:
        if forward_port not in host_vars["portforwards"]:
            host_vars["portforwards"].append(forward_port)

def get_hosts(hosts_yaml):
    """
    Get host information from the ansible configuration
    """
    hosts = {}
    for host in hosts_yaml[BACKEND_NAME]["hosts"]:
        hosts[host] = get_ip_address(hosts_yaml[BACKEND_NAME]["hosts"][host])
    for host in hosts_yaml[RELAY_NAME]["hosts"]:
        hosts[host] = get_ip_address(hosts_yaml[RELAY_NAME]["hosts"][host])

    # Gophish hosts have their admin interface ports defined in the hosts file
    if GOPHISH_NAME in hosts_yaml:
        for host in hosts_yaml[GOPHISH_NAME]["hosts"]:
            forward = get_portforward(hosts_yaml[GOPHISH_NAME]["hosts"][host], "gophish_admin_port")
            # Loop over all existing hosts to find the one with matching IP Address, as names can differ
            for hostname in hosts:
                if hosts[hostname]["address"] == forward["address"]:
                    host_vars = hosts[hostname]
                    add_to_forwards(host_vars, forward["forward"])


    # OSINT machines currently have no port defined in the hosts file, but expose RDP
    if OSINT_NAME in hosts_yaml:
        for host in hosts_yaml[OSINT_NAME]["hosts"]:
            address = hosts_yaml[OSINT_NAME]["hosts"][host]['ansible_host']
            for hostname in hosts_yaml['backends']["hosts"]:
                if hosts_yaml['backends']["hosts"][hostname]['ansible_host'] == address:
                    add_to_forwards(hosts[hostname], 3389)

    # CobaltStrike machines currently have no port defined in the hosts file, but expose 50050
    if COBALTSTRIKE_NAME in hosts_yaml:
        for host in hosts_yaml[COBALTSTRIKE_NAME]["hosts"]:
            address = hosts_yaml[COBALTSTRIKE_NAME]["hosts"][host]["ansible_host"]
            # Loop over all existing hosts to find the one with matching IP Address, as names can differ
            for hostname in hosts:
                if hosts[hostname]["address"] == address:
                    host_vars = hosts[hostname]
                    add_to_forwards(host_vars, 50050)
    return hosts

def parse_yaml(filename):
    """
    Safely parse the YAML file from disk
    """
    with open(filename, 'r') as stream:
        return yaml.safe_load(stream)

def create_host_string(hostname, host_vars, codename):
    """
    Create YAML configuration from a Jinja2 template
    """
    if "portforwards" not in host_vars:
        host_vars["portforwards"] = []
    return Environment().from_string(HOST_TEMPLATE).render(
                                    name=hostname,
                                    codename=codename,
                                    ip_address=host_vars["address"],
                                    portforwards=host_vars["portforwards"])

def create_ssh_config(hosts, codename):
    """
    Create and print the SSH configuration
    """
    for hostname in hosts:
        host_vars = hosts[hostname]
        print(create_host_string(hostname, host_vars, codename))

def main():
    """
    Parse and process the hosts
    """
    parser = argparse.ArgumentParser(
        description="Creates an SSH Config file from an Ansible Hosts file for Red Teaming"
    )

    parser.add_argument('directory', type=str, help='Provide the path to the config directory')
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    hosts_yaml = parse_yaml(options.directory + "/hosts.yml")
    config_yaml = parse_yaml(options.directory + "/configuration.yml")
    codename = config_yaml["codename"]

    hosts = get_hosts(hosts_yaml)
    create_ssh_config(hosts, codename)

if __name__ == '__main__':
    main()

