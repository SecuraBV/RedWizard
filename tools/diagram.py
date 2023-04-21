#!/usr/bin/env python3
import os
import sys
import argparse
import yaml
from diagrams import Cluster, Diagram, Edge, Node
from diagrams.generic.os import Ubuntu
from diagrams.generic.network import VPN

# Colour definitions
BOLD_GREY = "\x1b[38;1m"
BOLD_YELLOW = "\x1b[33;1m"
BOLD_MAGENTA = "\x1b[35;1m"
BOLD_RED = "\x1b[31;1m"
BOLD_CYAN = "\x1b[36;1m"
RESET = "\x1b[0m"

script_dir = os.path.dirname(__file__)

def parse_yaml(filename):
    """ Simple function to read in a file as yaml """
    with open(filename, 'r') as stream:
        return yaml.safe_load(stream)


def gather_component(hosts_yaml, role, backend_ip):
    """
    Gather components from the configuration
    """
    components = []
    if role in hosts_yaml:
        for component in hosts_yaml[role]['hosts']:
            component_ip = hosts_yaml[role]['hosts'][component]['ansible_host']
            if component_ip == backend_ip:
                components.append(component)
    return components


def gather_deployed_backend_components(hosts_yaml, server):
    """
    Gather a list of different backend components
    """
    backend_components = {
        'backends_cobalt_strike' : [],
        'backends_web_catcher' : [],
        'backends_osint' : [],
        'backends_gophish' : [],
        'backends_manual_phish' : [],
        'backends_dropbox' : [],
    }
    server_ip = hosts_yaml['backends']['hosts'][server]['ansible_host']
    for role in backend_components:
        backend_components[role].extend(gather_component(hosts_yaml, role, server_ip))
    return backend_components


def gather_deployed_relay_components(hosts_yaml, server):
    """
    Gather a list of deployed relay components
    """
    backend_components = {
        'relays_nginx' : [],
        'relays_osint' : [],
        'relays_phishing' : [],
        'relays_dropbox' : [],
        'relays_evilginx2' : []
    }
    server_ip = hosts_yaml['relays']['hosts'][server]['ansible_host']
    for role in backend_components:
        backend_components[role].extend(gather_component(hosts_yaml, role, server_ip))
    return backend_components


def get_phishing_campaigns(hosts_yaml, backend_components):
    """
    Gather a list of deployed phishing campaigns
    """
    phishing_campaigns = {}
    for role in backend_components:
        for component in backend_components[role]:
            if role in ['backends_gophish', 'backends_manual_phish']:
                domain_name = hosts_yaml[role]['hosts'][component]['domain_name']
                if domain_name not in phishing_campaigns:
                    phishing_campaigns[domain_name] = {}
                phishing_campaigns[domain_name][component] = role
    return phishing_campaigns


def role_backends_dropbox(hosts_yaml, backend_components):
    """
    Gather a list of deployed dropboxes
    """
    role = 'backends_dropbox'
    containers = []
    with Cluster(role):
        for name in backend_components[role]:
            relay_host = hosts_yaml[role]['hosts'][name]['relay_host']
            relay_host_ip = hosts_yaml[role]['hosts'][name]['relay_host_ip']
            current_container = {
                'role' : role,
                'name' : f"{name}\lRelay: {relay_host_ip}\l",
                'relay_host' : relay_host,
                'relay_host_ip' : relay_host_ip,
            }
            image_path = os.path.abspath(os.path.join(script_dir, 'resources/raspberrypi-backend-logo.png'))
            current_container['node'] = Node(current_container['name'], image=image_path, width="2", height="2", imagescale="true", penwidth="0", imagepos="lc")
            containers.append(current_container)
    return containers


def role_backends_cobalt_strike(hosts_yaml, backend_components):
    """
    Gather a list of deployed cobalt strike instances
    """
    role = 'backends_cobalt_strike'
    containers = []
    with Cluster(role):
        for name in backend_components[role]:
            relay_host = hosts_yaml[role]['hosts'][name]['relay_host']
            relay_host_ip = hosts_yaml[role]['hosts'][name]['relay_host_ip']
            malleable_profile = hosts_yaml[role]['hosts'][name]['malleable_profile']
            current_container = {
                'role' : role,
                'name' : f"{name}\lRelay: {relay_host_ip}\lProfile: {malleable_profile}\l",
                'relay_host' : relay_host,
                'relay_host_ip' : relay_host_ip,
            }
            image_path = os.path.abspath(os.path.join(script_dir, 'resources/cobaltstrike-logo.png'))
            current_container['node'] = Node(current_container['name'], image=image_path, width="2", height="2", imagescale="true", penwidth="0", imagepos="tc")
            containers.append(current_container)
    return containers


def role_backends_web_catcher(hosts_yaml, backend_components):
    """
    Gather a list of deployed web catchers
    """
    role = 'backends_web_catcher'
    containers = []
    with Cluster(role):
        for name in backend_components[role]:
            relay_host = hosts_yaml[role]['hosts'][name]['relay_host']
            relay_host_ip = hosts_yaml[role]['hosts'][name]['relay_host_ip']
            current_container = {
                'role' : role,
                'name' : f"{name}\lRelay: {relay_host_ip}\l",
                'relay_host' : relay_host,
                'relay_host_ip' : relay_host_ip,
            }
            image_path = os.path.abspath(os.path.join(script_dir, 'resources/webcatcher-logo.png'))
            current_container['node'] = Node(current_container['name'], image=image_path, width="2", height="2", imagescale="true", penwidth="0", imagepos="tc")
            containers.append(current_container)
    return containers


def role_backends_osint(hosts_yaml, backend_components):
    """
    Gather a list of deployed OSINT backends
    """
    role = 'backends_osint'
    containers = []
    with Cluster(role):
        for name in backend_components[role]:
            relay_host = hosts_yaml[role]['hosts'][name]['relay_host']
            relay_host_ip = hosts_yaml[role]['hosts'][name]['relay_host_ip']
            current_container = {
                'role': role,
                'name': f"Always on VPN\l",
                'relay_host': relay_host,
                'relay_host_ip': relay_host_ip,
            }
            current_container['node'] = VPN(current_container['name'], width="1.5")
            containers.append(current_container)
    return containers


def role_backends_phish(hosts_yaml, backend_components):
    """
    Gather a list of GoPhish backends
    """
    phishing_campaigns = get_phishing_campaigns(hosts_yaml, backend_components)
    containers = []
    for campaign in phishing_campaigns:
        campaign_name = f"Phishing Campaign: {campaign}"
        with Cluster(campaign_name):
            for name in phishing_campaigns[campaign]:
                role = phishing_campaigns[campaign][name]
                relay_host = hosts_yaml[role]['hosts'][name]['relay_host']
                relay_host_ip = hosts_yaml[role]['hosts'][name]['relay_host_ip']
                current_container = {
                    'role': role,
                    'name': f"{name}\lRelay: {relay_host_ip}\l",
                    'relay_host' : relay_host,
                    'relay_host_ip': relay_host_ip,
                }
                if role == 'backends_gophish':
                    image_path = os.path.abspath(os.path.join(script_dir, 'resources/gophish-logo.png'))
                else:
                    image_path = os.path.abspath(os.path.join(script_dir, 'resources/mutt-logo.png'))
                current_container['node'] = Node(
                    current_container['name'],
                    image=image_path,
                    width="2", height="2",
                    imagescale="true",
                    penwidth="0", imagepos="tc")
                containers.append(current_container)
    return containers


def create_backend_roles(hosts_yaml, diagram_node, backend_components):
    """
    Create a list of diagram edges based on containers
    """
    containers = []
    for role in backend_components:
        if len(backend_components[role]) > 0:
            if role == 'backends_dropbox':
                containers.extend(role_backends_dropbox(hosts_yaml, backend_components))
            if role == 'backends_cobalt_strike':
                containers.extend(role_backends_cobalt_strike(hosts_yaml, backend_components))
            if role == 'backends_web_catcher':
                containers.extend(role_backends_web_catcher(hosts_yaml, backend_components))
            if role == 'backends_osint':
                containers.extend(role_backends_osint(hosts_yaml, backend_components))
    containers.extend(role_backends_phish(hosts_yaml, backend_components))

    for container in containers:
        diagram_node - Edge(style='invis') - container['node']
    return containers


def create_backend_infra(hosts_yaml):
    """
    Create group clusters for backend infrastructure
    """
    if 'backends' in hosts_yaml:
        backend_servers = {}
        with Cluster("Backend Infrastructure", direction="LR"):
            for server in hosts_yaml['backends']['hosts']:
                backend_components = gather_deployed_backend_components(hosts_yaml, server)
                with Cluster(server):
                    ip_address = hosts_yaml['backends']['hosts'][server]['ansible_host']
                    server_name = f"{server}\n{ip_address}"
                    node = Ubuntu(server_name)
                    backend_servers[server] = {
                        'node': node,
                        'containers': create_backend_roles(hosts_yaml, node, backend_components)
                    }

        return backend_servers


def role_relays_dropbox(hosts_yaml, relay_components):
    """
    Create a list of deployed dropbox relays
    """
    role = 'relays_dropbox'
    containers = []
    with Cluster(role):
        for name in relay_components[role]:
            exposed_port = hosts_yaml[role]['vars']['exposed_port']
            current_container = {
                'role' : role,
                'name' : f'{name}\lExposed Port: {exposed_port}\l',
                'exposed_port' : exposed_port,
            }
            image_path = os.path.abspath(os.path.join(script_dir, 'resources/raspberrypi-backend-logo.png'))
            current_container['node'] = Node(current_container['name'], image=image_path, width="2.5", height="2", imagescale="true", penwidth="0")
            containers.append(current_container)
    return containers


def role_relays_nginx(hosts_yaml, relay_components):
    """
    Create a list of deployed Nginx relays
    """
    role = 'relays_nginx'
    containers = []
    with Cluster(role):
        for name in relay_components[role]:
            # exposed_port = hosts_yaml[role]['vars']['exposed_port']
            relay_for = hosts_yaml[role]['hosts'][name]['relay_to_client_profile']
            domain_name = hosts_yaml[role]['hosts'][name]['domain_name']
            current_container = {
                'role' : role,
                'name' : f'{name}\lRelay for: {relay_for}\lDomain:\l{domain_name}\l',
                'relay_to_client_profile' : relay_for,
                'domain_name' : domain_name
                # 'exposed_port' : exposed_port,
            }
            image_path = os.path.abspath(os.path.join(script_dir, 'resources/nginx-logo.png'))
            current_container['node'] = Node(current_container['name'], image=image_path, width="2.5", height="2", imagescale="true", penwidth="0", imagepos="tc")
            containers.append(current_container)
    return containers


def role_relays_phish(hosts_yaml, relay_components):
    """
    Create a list of phishing relays
    """
    role = 'relays_phishing'
    containers = []
    with Cluster(role):
        for name in relay_components[role]:
            domain_name = hosts_yaml[role]['hosts'][name]['domain_name']
            current_container = {
                'role' : role,
                'name': f'{name}\lMailserver for:\l{domain_name}\l',
                'domain_name': domain_name
                # 'exposed_port' : exposed_port,
            }
            image_path = os.path.abspath(os.path.join(script_dir, 'resources/postfix-logo.png'))
            current_container['node'] = Node(current_container['name'], image=image_path, width="2.5", height="2", imagescale="true", penwidth="0", imagepos="tc")
            containers.append(current_container)
    return containers


def role_relays_osint(hosts_yaml, relay_components):
    """
    Create a list of OSINT relays
    """
    role = 'relays_osint'
    containers = []
    with Cluster(role):
        for name in relay_components[role]:
            # exposed_port = hosts_yaml[role]['vars']['exposed_port']
            current_container = {
                'role' : role,
                'name' : f'{name}\lRelay all traffic for OSINT\l',
                # 'exposed_port' : exposed_port,
            }
            image_path = os.path.abspath(os.path.join(script_dir, 'resources/openvpn-logo.png'))
            current_container['node'] = Node(current_container['name'], image=image_path, width="2.5", height="2", imagescale="true", penwidth="0", imagepos="tc")
            containers.append(current_container)
    return containers


def create_relay_roles(hosts_yaml, diagram_node, relay_components):
    """
    Create edges for the relay roles
    """
    containers = []
    roles = []
    for role in relay_components:
        if len(relay_components[role]) > 0:
            if role == 'relays_osint':
                containers.extend(role_relays_osint(hosts_yaml, relay_components))
            if role == 'relays_dropbox':
                containers.extend(role_relays_dropbox(hosts_yaml, relay_components))
            if role == 'relays_phishing':
                containers.extend(role_relays_phish(hosts_yaml, relay_components))
            if role == 'relays_nginx':
                containers.extend(role_relays_nginx(hosts_yaml, relay_components))

    for container in containers:
        diagram_node - Edge(style='invis') -  container['node']
    return containers


def create_relay_infra(hosts_yaml):
    """
    Create the objects for the relay infrastrucrue
    """
    if 'relays' in hosts_yaml:
        relay_servers = {}
        with Cluster("Relay Infrastructure", direction="LR"):
            for server in hosts_yaml['relays']['hosts']:
                relay_components = gather_deployed_relay_components(hosts_yaml, server)
                with Cluster (server):
                    ip_address = hosts_yaml['relays']['hosts'][server]['ansible_host']
                    server_name = f"{server}\n{ip_address}"
                    node = Ubuntu(server_name)
                    relay_servers[server] = {
                        'node': node,
                        'ip_address': ip_address,
                        'containers': create_relay_roles(hosts_yaml, node, relay_components)
                    }
        return relay_servers


def link_backend_to_relays(backend_servers, relay_servers):
    """
    Link the backend servers to the relay servers
    """
    for server in backend_servers:
        for container in backend_servers[server]['containers']:
            backend_container_node = container['node']
            relay_server_for_container = container['relay_host_ip']
            for relay in relay_servers:
                if relay_servers[relay]['ip_address'] == relay_server_for_container:
                    backend_container_node >> Edge(tailport='s') >> relay_servers[relay]['node']


def create_diagram(hosts_yaml, filename):
    """
    Create the infrastructure diagram
    """
    graph_attr = {
        "splines": "curved",
        "constraint": "false"
    }
    with Diagram(name="Infra Deployment", show=False, outformat="jpg",
                 filename=filename, direction="TB", graph_attr=graph_attr):
        with Cluster ("Infrastructure"):
            backend_servers = create_backend_infra(hosts_yaml)
            relay_servers = create_relay_infra(hosts_yaml)
            link_backend_to_relays(backend_servers, relay_servers)
    print("Created diagram in %s.jpg" % filename)


def main():
    """ Main function """
    parser = argparse.ArgumentParser(description="Creates a hosts.yml configuration file\
                                                  for the Ansible RT Infrastructure deployment.\
                                                  This can either create a new one or modify\
                                                  an existing one.")

    parser.add_argument('directory', type=str, help='The target directory with the source hosts file')
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    hosts_yaml_location = os.path.join(options.directory, 'hosts.yml')
    diagram_location = os.path.join(options.directory, 'diagram')
    if os.path.exists(hosts_yaml_location):
        print("Hosts file found, creating diagram")
        hosts_yaml = parse_yaml(hosts_yaml_location)
    else:
        print("Hosts file not found in %s, exiting" % hosts_yaml_location)
        sys.exit(1)
    create_diagram(hosts_yaml, diagram_location)


if __name__ == '__main__':
    main()
