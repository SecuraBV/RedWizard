#!/usr/bin/python3
""" Script to automate and guide the creation of a Red Teaming inventory """
import os
import sys
import argparse
import uuid
import re
import validators
from IPy import IP
import yaml
from tools.util.jinja_templating import get_jinja_env


###############################################################################
# Constants
###############################################################################

# Jinja2 Templating is used to create the hosts file
HOSTS_TEMPLATE = 'hosts.yml'

# The number of secret strings to generate for reverse nginx-proxies.
# Must at least be 4 in order to support CobaltStrike
NR_OF_SECRET_STRINGS = 4

# Indicate the port that should be exposed for incoming dropboxes
DROPBOX_EXPOSE_PORT = 8896

# Some default values we usually don't need to change. Consider changing in your deploy
DEFAULT_VARS = {
    'relays_phishing': {'client_profiles': ['gophish', 'manual-phish']},
    'relays_osint': {'client_profiles': ['osint']},
    'backends_gophish': {'send_from': ['info@', 'no-reply@', 'service@', 'servicedesk@']},
    'relays_dropbox': {'dropbox_docker_ip':'10.8.0.99', 'exposed_port' : DROPBOX_EXPOSE_PORT, 'client_profiles': ['dropbox']},
    'backends_dropbox': {'exposed_port' : DROPBOX_EXPOSE_PORT},
    'relays_nginx': {'client_profiles': ['manual-phish', 'gophish', 'cobaltstrike', 'web-catcher']},
    }

# This defines the different types of servers present
SERVERS = {
    'backends': ['name', 'ansible_host'],
    'relays': ['name', 'ansible_host'],
    }

# All deployable rules are designated here. Additionally, this includes
# all neccesary values in order to deploy the role
ROLES = {
    'relays_phishing': ['name', 'domain_name', 'ansible_host'],
    'relays_osint': ['name', 'ansible_host'],
    'relays_nginx': ['name', 'backend_port', 'domain_name', 'nginx_bounce_site', 'relay_to_client_profile', 'secret_strings', 'ansible_host'],
    'relays_dropbox': ['name', 'ansible_host'],
    'relays_cobalt_strike': ['name', 'domain_name', 'ansible_host', 'relay_to_client_profile', 'dns_beacon_subdomain'],
    'backends_cobalt_strike': ['name', 'domain_name', 'http_get_uri', 'http_post_uri', 'http_stager_64_uri', 'http_stager_86_uri', 'identification', 'malleable_profile', 'relay_host', 'relay_host_ip', 'ansible_host', 'dns_beacon_subdomain'],
    'backends_web_catcher': ['name', 'relay_host', 'relay_host_ip', 'ansible_host'],
    'backends_dropbox': ['name', 'relay_host', 'relay_host_ip', 'exposed_port', 'ansible_host'],
    'backends_redelk': ['name', 'relay_host', 'relay_host_ip', 'ansible_host'],
    'backends_osint': ['name', 'ansible_host', 'relay_host', 'relay_host_ip'],
    'backends_gophish': ['name', 'domain_name', 'gophish_admin_port', 'relay_host', 'relay_host_ip', 'ansible_host'],
    'backends_manual_phish': ['name', 'domain_name', 'relay_host', 'relay_host_ip', 'ansible_host'],
    }



# Roles that can only be deployed on the server once
UNIQUE_ROLES = [
    'relays_phishing',
    'relays_dropbox',
    'relays_osint',
    'backends_redelk',
    'backends_osint',
    ]

# Help texts for the ansible variables
HELP = {
    'name': 'Server/Role Designation, for example C2, Relay-Phish-1, etc',
    'ansible_host': "IP Address of the server",
    'domain_name': "Domain name associated with this component, MUST Point to this relay server",
    'backend_port': "On what port is the backend docker listening? (Default: 80)",
    'nginx_bounce_site': "To where should the target be bounced when incorrect URL is provided? (Include http:// etc)",
    'relay_to_client_profile': "THIS NEEDS A CHOICE",
    'secret_strings': "THIS NEEDS A CHOICE",
    'identification': "Identification for this CS Campaign",
    'gophish_admin_port': "Default port exposed on the docker container (NEEDS TO BE UNIQUE FOR ALL GoPhish INSTANCES ON THE SAME SERVER!), use something like 13337/13338",
    'CampaignName':'Indicate the name of the campaign (Alphanumeric only), should be unique in your deployment',
    'malleable_profile':'The malleable profile you want to use. Choose one you configured in the CobaltStrike role. By default use: browser.profile',
    'dns_beacon_subdomain':'The subdomain that you configured as nameserver for your CS DNS beacons. for example "a"',
}

# If show help, prompts will be longer and include more info
SHOW_HELP = True

# Colour definitions
BOLD_GREY = "\x1b[38;1m"
BOLD_YELLOW = "\x1b[33;1m"
BOLD_MAGENTA = "\x1b[35;1m"
BOLD_RED = "\x1b[31;1m"
BOLD_CYAN = "\x1b[36;1m"
RESET = "\x1b[0m"

###############################################################################
# IO Functions to read and write yaml files
###############################################################################


def write_template(out_file, output):
    """ Writes the completed template to the designated outfile """
    confirmation = input(f"\n{BOLD_RED}Saving inventory to {out_file}, are you sure? y/n{RESET}\n")
    if not(confirmation == 'Y' or confirmation == 'y'):
        return
    try:
        with open(out_file, 'w') as file_handler:
            file_handler.truncate()  # Clear the files before we start
            file_handler.write(output)
            print(f'{BOLD_RED}Saved{RESET}')
    except FileNotFoundError:
        print("Unable to write to %s" % str(out_file))
        raise
    except OSError as os_error:
        print(f"Error opening file: {os_error:}")
        raise

def create_hosts_template(out_file, all_hosts):
    """ Sets all the neccesary variables to print the jinja2 template """
    formatted_hosts = {}
    for key in all_hosts.keys():
        formatted_hosts[key] = pretty_print(all_hosts, key)

    jinja_env = get_jinja_env()
    template = jinja_env.get_template(HOSTS_TEMPLATE)

    output = template.render(formatted_hosts)

    write_template(out_file, output)


def parse_yaml(filename):
    """ Simple function to read in a file as yaml """
    with open(filename, 'r') as stream:
        return yaml.safe_load(stream)

###############################################################################
# Input Validation functions
###############################################################################

def get_all_names(hosts_yaml):
    names = []
    for role in hosts_yaml:
        for host in hosts_yaml[role]['hosts']:
            names.append(host)
    return names

def get_server_nr(server_type, hosts_yaml):
    count = 0
    if not hosts_yaml:
        return 0
    if server_type in hosts_yaml:
        for _ in hosts_yaml[server_type]['hosts']:
            count += 1
    return count

def validate_input(input_field, value, hosts_yaml):
    IP_ADDRESSES = ['ansible_host', 'relay_host_ip']
    NUMBER = ['backend_port', 'gophish_admin_port',]
    STRING = ['identification', 'send_from', 'relay_host', 'dns_beacon_subdomain']
    NAME = ['name']
    CAMPAIGN_NAME = ['CampaignName']
    DOMAIN = ['domain_name']
    URL = ['nginx_bounce_site']

    try:
        if input_field in IP_ADDRESSES:
            IP(value)

        elif input_field in NUMBER:
            if not value.isdigit():
                print('Provided value is not a number')
                return False

        elif input_field in STRING:
            if (' ' in value) or \
                ('"' in value) or \
                ("'" in value) or \
                ('/' in value) or \
                ('\\' in value):
                print('Provided value is not a valid string')
                return False

        elif input_field in NAME:
            names = get_all_names(hosts_yaml)
            if value in names:
                print('Provided name already exists')
                return False
        elif input_field in CAMPAIGN_NAME:
            if not value.isalnum():
                print('Provided value is not alphanumeric')
                return False
        elif input_field in DOMAIN:
            if not re.match(r'''
            (?=^.{,253}$)          # max. length 253 chars
            (?!^.+\.\d+$)          # TLD is not fully numerical
            (?=^[^-.].+[^-.]$)     # doesn't start/end with '-' or '.'
            (?!^.+(\.-|-\.).+$)    # levels don't start/end with '-'
            (?:[a-z\d-]            # uses only allowed chars
            {1,63}(\.|$))          # max. level length 63 chars
            {2,127}                # max. 127 levels
            ''',value, re.X | re.I):
                return False
        elif input_field in URL:
            if not validators.url(value):
                return False
    except:
        return False
    return True

###############################################################################
# Print functions
###############################################################################

def pretty_print(yml_dict, key):
    """ Pretty prints a dictionary into predefined yaml format """
    try:
        toplevel = {key : yml_dict[key]}
        return yaml.dump(toplevel, width=80, indent=4, default_flow_style=False)
        #return yaml.dump(yml_dict[key], width=80, indent=4, default_flow_style=False)
    except KeyError:
        return ""

def print_role_info(host, role):
    """ Simple print to show the role and host relation """
    print(f"- {role} designated {BOLD_CYAN}{host}{RESET}")

def print_server_roles(hosts_yaml, server, server_type):
    """ Prints all deployed roles to a server """
    try:
        server_ip = hosts_yaml[server_type]['hosts'][server]['ansible_host']
        print(f"\n{BOLD_RED}{server}{RESET} ({server_ip}) and has the following roles:")
    except (KeyError, TypeError):
        pass
    for role in ROLES:
        if role in hosts_yaml:
            for host in hosts_yaml[role]['hosts']:
                if host == server:
                    print_role_info(host, role)
                else:
                    try:
                        host_ip = hosts_yaml[role]['hosts'][host]['ansible_host']
                        server_ip = hosts_yaml[server_type]['hosts'][server]['ansible_host']
                        if host_ip == server_ip:
                            print_role_info(host, role)
                    except (KeyError, TypeError):
                        continue

def show_inventory(hosts_yaml):
    """ Simply gives the full inventory as a dumped yaml string """
    print(yaml.dump(hosts_yaml, width=80, indent=4, default_flow_style=False))


###############################################################################
# Functions to change data in the yaml
###############################################################################

def add_server(role, value_set, hosts_yaml):
    new_name = value_set['name']
    # Case: this is the first deployment in the role
    if role not in hosts_yaml:
        hosts_yaml[role] = {'hosts' : {}}

    # Case: This host does not yet exist
    if not new_name in hosts_yaml[role]['hosts']:
        hosts_yaml[role]['hosts'][new_name] = {}

    # Write all relevant variables
    for key in value_set:
        if not key == 'name':
            hosts_yaml[role]['hosts'][new_name][key] = value_set[key]

    # Add default variables
    if role in DEFAULT_VARS:
        if not 'vars' in hosts_yaml[role]:
            hosts_yaml[role]['vars'] = DEFAULT_VARS[role]

###############################################################################
# Menu Helper functions
###############################################################################

def show_menu(menu, message, suppress_exit=False):
    """
    Displays a dictionary of options as a menu.
    Keys are presented as options, and the corresponding value is returned
    after choosing that option
    """
    print(f"\n{BOLD_YELLOW}{message}{RESET}")
    while True:
        options = menu.keys()
        choice_menu = {}
        choice = 0
        for entry in options:
            choice += 1
            choice_menu[str(choice)] = (entry, menu[entry])
            print(choice, entry)

        # Always add an exit statement
        if not suppress_exit:
            print('x Exit')
        selection = input("\nPlease Select: ")
        try:
            # Exit statement to break out of the loop
            if selection == 'x':
                value = "Exit"
            else:
                _, value = choice_menu[str(selection)]
            return value
        except (KeyError, TypeError):
            print("\nUnknown Option Selected!\n")


def request_secret_strings():
    menu = {
        'Manual' : 'manual',
        'Randomized' : 'random'
    }

    choice = show_menu(menu, f"Choose if you want to manually define secret strings, or auto-generate them")
    strings = []
    if choice == "Exit":
        return None
    elif choice == 'random':
        for i in range(NR_OF_SECRET_STRINGS):
            strings.append(str(uuid.uuid4()))
    else:
        for i in range(NR_OF_SECRET_STRINGS):
            strings.append(input(f"{BOLD_YELLOW}Value for secret string {i+1}/{NR_OF_SECRET_STRINGS}{RESET}:\n"))
    return strings

def request_data(question_set, hosts_yaml):
    """
    Request user input to a select set of questions
    Questions have the following format:
    ['variable1','variable2']
    The question will than be asked in the following form:
    Value for <variable1> (Optional Help Text)
    """
    values = {}
    for item in question_set:
        if item == 'secret_strings':
            values[item] = request_secret_strings()
            continue
        while True:
            if SHOW_HELP:
                helptext = HELP[item]
                values[item] = input(f"\nValue for {BOLD_YELLOW}{item.upper()}{RESET} ({helptext}):\n")
            else:
                values[item] = input(f"\nValue for {BOLD_YELLOW}{item.upper()}{RESET}:\n")
            if not validate_input(item, values[item], hosts_yaml):
                print(f'\n{BOLD_RED}Invalid value! Please try again{RESET}\n')
            else:
                break
    return values


def check_if_role_deployed(role, server, server_ip, hosts_yaml):
    """ Checks if a role is already deployed to a server """
    if role in hosts_yaml:
        for host in hosts_yaml[role]['hosts']:
            if host == server:
                return True
            else:
                try:
                    host_ip = hosts_yaml[role]['hosts'][host]['ansible_host']
                    if host_ip == server_ip:
                        return True
                except (KeyError, TypeError):
                    continue
    return False

###############################################################################
# Menus
###############################################################################

def target_server_menu(hosts_yaml, server_type):
    """ This menu lets the user pick to what server a role should be deployed """
    value_set = {}
    if server_type == "Exit":
        return None
    if server_type in ROLES.keys() and server_type.startswith('relay'):
        eligible_hosts = 'relays'
    elif server_type in ROLES.keys() and server_type.startswith('backends'):
        eligible_hosts = 'backends'

    menu = {}
    for server in hosts_yaml[eligible_hosts]['hosts']:
        hosts_ip = hosts_yaml[eligible_hosts]['hosts'][server]['ansible_host']
        deployed = check_if_role_deployed(server_type, server, hosts_ip, hosts_yaml)
        if deployed and server_type in UNIQUE_ROLES:
            menu[f'{BOLD_RED}{server} ({hosts_ip}) NOT ELIGIBLE, ROLE ALREADY DEPLOYED{RESET}'] = server
        else:
            menu[f'{server} ({hosts_ip})'] = hosts_ip
    value_set['ansible_host'] = show_menu(menu, f"Choose {eligible_hosts} server to deploy this to")
    if value_set['ansible_host'] == 'Exit':
        return None
    return value_set

def add_server_menu(hosts_yaml):
    """ Menu to show what base servers should be deployed """
    servers = SERVERS.keys()
    servers_menu = {}
    for server in servers:
        servers_menu[server] = server
    choice = show_menu(servers_menu, "What type of server do you want to deploy?")
    if choice == "Exit":
        return

    print(f"\nCurrent servers in the category '{BOLD_RED}{choice}{RESET}':")
    for item in hosts_yaml[choice]['hosts']:
        print_server_roles(hosts_yaml, item, choice)
        #print(f'- {item}')
    print("")
    value_set = request_data(SERVERS[choice], hosts_yaml)
    add_server(choice, value_set, hosts_yaml)
    print(f"\n{BOLD_CYAN}Added the following server:{RESET}")
    print(f"{BOLD_CYAN}- {value_set['name']} on {value_set['ansible_host']}{RESET}")

def add_dropbox_menu(hosts_yaml):
    """ Menu to request information about a phishing campaign """

    # Send the user to the next menu where more information about the new role
    # is requested
    c2_value_set = target_server_menu(hosts_yaml, 'backends_dropbox')
    if not c2_value_set:
        return
    relay_value_set = target_server_menu(hosts_yaml, 'relays_dropbox')
    if not relay_value_set:
        return
    question_set = ['CampaignName']
    request_value_set = request_data(question_set, hosts_yaml)

    relay_value_set = {
        'name' : f"Dropbox-Relay-{request_value_set['CampaignName']}",
        'ansible_host' : relay_value_set["ansible_host"],
    }

    backend_value_set = {
        'name' : f"Dropbox-{request_value_set['CampaignName']}",
        'ansible_host' : c2_value_set["ansible_host"],
        'relay_host' : f"Dropbox-Relay-{request_value_set['CampaignName']}",
        'relay_host_ip': relay_value_set["ansible_host"],
    }


    add_server('relays_dropbox', relay_value_set, hosts_yaml)
    add_server('backends_dropbox', backend_value_set, hosts_yaml)
    print(f"\n{BOLD_CYAN}Added the following roles:{RESET}")
    print(f"{BOLD_CYAN}- backends_dropbox to {c2_value_set['ansible_host']}{RESET}")
    print(f"{BOLD_CYAN}- relays_dropbox to {relay_value_set['ansible_host']}{RESET}")

def add_osint_menu(hosts_yaml):
    """ Menu to request information about a phishing campaign """

    print(f"""
{BOLD_RED}>>> IMPORTANT <<<\nChoose a Backend server with no other roles, besides this OSINT role.
This role needs to be deployed on it's own Backend. Otherwise stuff will break!
There are no current checks to prevent you from adding it to the wrong server!
>>> IMPORTANT <<<{RESET}
    """)
    # Send the user to the next menu where more information about the new role
    # is requested
    c2_value_set = target_server_menu(hosts_yaml, 'backends_osint')
    relay_value_set = target_server_menu(hosts_yaml, 'relays_osint')
    question_set = ['CampaignName']
    request_value_set = request_data(question_set, hosts_yaml)

    osint_relay_value_set = {
        'name' : f"OSINT-Relay-{request_value_set['CampaignName']}",
        'ansible_host' : relay_value_set["ansible_host"],
    }

    osint_backend_value_set = {
        'name' : f"OSINT-{request_value_set['CampaignName']}",
        'ansible_host' : c2_value_set["ansible_host"],
        'relay_host' : f"OSINT-Relay-{request_value_set['CampaignName']}",
        'relay_host_ip': relay_value_set["ansible_host"],
    }


    add_server('relays_osint', osint_relay_value_set, hosts_yaml)
    add_server('backends_osint', osint_backend_value_set, hosts_yaml)
    print(f"\n{BOLD_CYAN}Added the following roles:{RESET}")
    print(f"{BOLD_CYAN}- backends_osint to {c2_value_set['ansible_host']}{RESET}")
    print(f"{BOLD_CYAN}- relays_osint to {relay_value_set['ansible_host']}{RESET}")

def get_malleable_profiles():
    profiles = []
    for file in os.listdir("roles/backend-cobalt-strike/templates/"):
        if file.endswith("profile.j2"):
            profiles.append(file[:-3])
    return profiles

def add_malleable_profile_menu(profiles):
    """ Menu to show what profile should be deployed """
    profiles_menu = {}
    for profile in profiles:
        profiles_menu[profile] = profile
    choice = show_menu(profiles_menu, "What profile do you want to deploy? (You can add your own profiles in roles/backend-cobalt-strike/templates/)", True)
    return choice

def add_cobaltstrike_menu(hosts_yaml):
    """ Menu to request information about a cobaltstrike campaign """

    print(f"""
{BOLD_YELLOW}>>> IMPORTANT <<<\nSecret strings you select will matter how the CS profile in configured!
Secret String 0: http_get_uri
Secret String 1: http_post_uri
Secret String 2: http_stager_86_uri
Secret String 3: http_stager_64_uri
The values you choose will automatically updated in the malleable profile
>>> IMPORTANT <<<{RESET}
    """)
    base_dir = os.path.dirname(os.path.realpath(__file__))
    cs_path = "{}/roles/backend-cobalt-strike/files/docker/cobaltstrike-dist.tgz".format(base_dir)
    cs_binary_exists = os.path.exists(cs_path)
    if not cs_binary_exists:
        print(f"""
{BOLD_RED}>>> IMPORTANT <<<\n{cs_path}
DOES NOT EXIST
If you want to install CobaltStrike you need to put your own binary in this path
>>> IMPORTANT <<<{RESET}
    """)
    c2_value_set = target_server_menu(hosts_yaml, 'backends_cobalt_strike')
    if not c2_value_set:
        return
    relay_value_set = target_server_menu(hosts_yaml, 'relays_nginx')
    if not relay_value_set:
        return
    question_set = ['CampaignName', 'domain_name', 'nginx_bounce_site', 'secret_strings', 'dns_beacon_subdomain']

    request_value_set = request_data(question_set, hosts_yaml)
    profiles = get_malleable_profiles()
    profile = add_malleable_profile_menu(profiles)
    request_value_set['malleable_profile'] = profile

    nginx_secret_strings = []
    for value in request_value_set['secret_strings']:
        nginx_secret_strings.append({
            'string' : f'{value}/',
            'forward_path' : f"/{value}/",
            'connection_method' : "https"
        })
    nginx_relay_value_set = {
        'name' : f"Nginx-CobaltStrike-{request_value_set['CampaignName']}",
        'ansible_host' : relay_value_set["ansible_host"],
        'backend_port' : 443,
        'domain_name' : request_value_set['domain_name'],
        'nginx_bounce_site' : request_value_set['nginx_bounce_site'],
        'relay_to_client_profile' : 'cobaltstrike',
        'secret_strings' : nginx_secret_strings,
    }

    cobaltstrike_relay_value_set = {
        'name' : f"Relay-CobaltStrike-{request_value_set['CampaignName']}",
        'ansible_host' : relay_value_set["ansible_host"],
        'domain_name' : request_value_set['domain_name'],
        'relay_to_client_profile' : 'cobaltstrike',
        'dns_beacon_subdomain' : request_value_set['dns_beacon_subdomain'],
    }

    cobaltstrike_backend_value_set = {
        'name' : f"CobaltStrike-{request_value_set['CampaignName']}",
        'ansible_host' : c2_value_set["ansible_host"],
        'relay_host' : f"Nginx-CobaltStrike-{request_value_set['CampaignName']}",
        'relay_host_ip': relay_value_set["ansible_host"],
        'identification': request_value_set['CampaignName'],
        'domain_name' : request_value_set['domain_name'],
        'http_get_uri' : request_value_set['secret_strings'][0],
        'http_post_uri' : request_value_set['secret_strings'][1],
        'http_stager_86_uri' : request_value_set['secret_strings'][2],
        'http_stager_64_uri' : request_value_set['secret_strings'][3],
        'malleable_profile' : request_value_set['malleable_profile'],
        'dns_beacon_subdomain' : request_value_set['dns_beacon_subdomain'],
    }


    add_server('relays_nginx', nginx_relay_value_set, hosts_yaml)
    add_server('backends_cobalt_strike', cobaltstrike_backend_value_set, hosts_yaml)
    add_server('relays_cobalt_strike', cobaltstrike_relay_value_set, hosts_yaml)
    print(f"\n{BOLD_CYAN}Added the following roles:{RESET}")
    print(f"{BOLD_CYAN}- backends_cobalt_strike to {c2_value_set['ansible_host']}{RESET}")
    print(f"{BOLD_CYAN}- relays_nginx to {relay_value_set['ansible_host']}{RESET}")
    print(f"{BOLD_CYAN}- relays_cobalt_strike to {relay_value_set['ansible_host']}{RESET}")

def add_webcatcher_menu(hosts_yaml):
    """ Menu to request information about a phishing campaign """

    # Send the user to the next menu where more information about the new role
    # is requested
    c2_value_set = target_server_menu(hosts_yaml, 'backends_web_catcher')
    if not c2_value_set:
        return
    relay_value_set = target_server_menu(hosts_yaml, 'relays_nginx')
    if not relay_value_set:
        return
    question_set = ['CampaignName', 'domain_name', 'nginx_bounce_site', 'secret_strings']


    request_value_set = request_data(question_set, hosts_yaml)

    nginx_secret_strings = []
    for value in request_value_set['secret_strings']:
        nginx_secret_strings.append({
            'string' : value + '/',
            'forward_path' : "/logger.php",
            'connection_method' : "http"
        })
    nginx_relay_value_set = {
        'name' : f"Nginx-Webcatcher-{request_value_set['CampaignName']}",
        'ansible_host' : relay_value_set["ansible_host"],
        'backend_port' : 80,
        'domain_name' : request_value_set['domain_name'],
        'nginx_bounce_site' : request_value_set['nginx_bounce_site'],
        'relay_to_client_profile' : 'web-catcher',
        'secret_strings' : nginx_secret_strings,
    }

    webcatcher_backend_value_set = {
        'name' : f"Webcatcher-{request_value_set['CampaignName']}",
        'ansible_host' : c2_value_set["ansible_host"],
        'relay_host' : f"Nginx-Webcatcher-{request_value_set['CampaignName']}",
        'relay_host_ip': relay_value_set["ansible_host"],
    }


    add_server('relays_nginx', nginx_relay_value_set, hosts_yaml)
    add_server('backends_web_catcher', webcatcher_backend_value_set, hosts_yaml)
    print(f"\n{BOLD_CYAN}Added the following roles:{RESET}")
    print(f"{BOLD_CYAN}- backends_web_catcher to {c2_value_set['ansible_host']}{RESET}")
    print(f"{BOLD_CYAN}- relays_nginx to {relay_value_set['ansible_host']}{RESET}")

def add_phish_menu(hosts_yaml):
    """ Menu to request information about a phishing campaign """

    # Send the user to the next menu where more information about the new role
    # is requested
    c2_value_set = target_server_menu(hosts_yaml, 'backends_gophish')
    if not c2_value_set:
        return
    relay_value_set = target_server_menu(hosts_yaml, 'relays_phishing')
    if not relay_value_set:
        return
    question_set = ['CampaignName', 'domain_name', 'nginx_bounce_site', 'gophish_admin_port', 'secret_strings']


    request_value_set = request_data(question_set, hosts_yaml)
    phish_relay_value_set = {
        'name' : f"Phish-Relay-{request_value_set['CampaignName']}",
        'ansible_host' : relay_value_set["ansible_host"],
        'domain_name' : request_value_set['domain_name']
    }

    nginx_secret_strings = []
    for value in request_value_set['secret_strings']:
        nginx_secret_strings.append({
            'string' : value + '/',
            'forward_path' : "/",
            'connection_method' : "http"
        })
    nginx_relay_value_set = {
        'name' : f"Nginx-Gophish-{request_value_set['CampaignName']}",
        'ansible_host' : relay_value_set["ansible_host"],
        'backend_port' : 80,
        'domain_name' : request_value_set['domain_name'],
        'nginx_bounce_site' : request_value_set['nginx_bounce_site'],
        'relay_to_client_profile' : 'gophish',
        'secret_strings' : nginx_secret_strings,
    }

    gophish_backend_value_set = {
        'name' : f"Gophish-{request_value_set['CampaignName']}",
        'relay_host' : f"Phish-Relay-{request_value_set['CampaignName']}",
        'ansible_host' : c2_value_set["ansible_host"],
        'relay_host_ip': relay_value_set["ansible_host"],
        'gophish_admin_port' : request_value_set['gophish_admin_port'],
        'domain_name' : request_value_set['domain_name'],
    }

    manual_phish_backend_value_set = {
        'name' : f"Manual-Phish-{request_value_set['CampaignName']}",
        'relay_host' : f"Phish-Relay-{request_value_set['CampaignName']}",
        'ansible_host' : c2_value_set["ansible_host"],
        'relay_host_ip': relay_value_set["ansible_host"],
        'domain_name' : request_value_set['domain_name'],
    }

    add_server('relays_phishing', phish_relay_value_set, hosts_yaml)
    add_server('relays_nginx', nginx_relay_value_set, hosts_yaml)
    add_server('backends_gophish', gophish_backend_value_set, hosts_yaml)
    add_server('backends_manual_phish', manual_phish_backend_value_set, hosts_yaml)
    print(f"\n{BOLD_CYAN}Added the following roles:{RESET}")
    print(f"{BOLD_CYAN}- backends_gophish, backends_manual_phish to {c2_value_set['ansible_host']}{RESET}")
    print(f"{BOLD_CYAN}- relays_phishing, relays_nginx to {relay_value_set['ansible_host']}{RESET}")

def initial_menu(hosts_yaml, hosts_yaml_location):
    """ The main menu """
    while True:
        menu = {f"Add Server{BOLD_GREY} (Basic Building Block){RESET}": "Add_Server"}

        # Show an option to add server roles if a server is already defined
        if get_server_nr('backends', hosts_yaml) + get_server_nr('relays', hosts_yaml) > 0:
            menu["Add Phishing Campaign"] = "Add_Phish"
            menu["Add Webcatcher Campaign"] = "Add_Webcatcher"
            menu["Add OSINT Campaign"] = "Add_OSINT"
            menu["Add CobaltStrike Campaign"] = "Add_CobaltStrike"
            menu["Add Dropbox Campaign"] = "Add_Dropbox"
        menu["Show Current Inventory"] = "Show"
        menu["Save Updated Inventory"] = "Save"

        choice = show_menu(menu, "Please choose your action")
        if choice == "Add_Server":
            add_server_menu(hosts_yaml)
        elif choice == "Save":
            create_hosts_template(hosts_yaml_location, hosts_yaml)
        elif choice == "Add_Phish":
            add_phish_menu(hosts_yaml)
        elif choice == "Add_Webcatcher":
            add_webcatcher_menu(hosts_yaml)
        elif choice == "Add_OSINT":
            add_osint_menu(hosts_yaml)
        elif choice == "Add_CobaltStrike":
            add_cobaltstrike_menu(hosts_yaml)
        elif choice == "Add_Dropbox":
            add_dropbox_menu(hosts_yaml)
        elif choice == "Show":
            show_inventory(hosts_yaml)
        elif choice == "Exit":
            confirmation = input(f"Are you sure? You might want to safe first. {BOLD_YELLOW} y/n{RESET}\n")
            if confirmation == 'Y' or confirmation == 'y':
                break

###############################################################################
# Main functions
###############################################################################

def print_ascii_art():
    print(r"")
    print(r"__________           .___  __      __.__                         .___")
    print(r"\______   \ ____   __| _/ /  \    /  \__|____________ _______  __| _/")
    print(r" |       _// __ \ / __ |  \   \/\/   /  \___   /\__  \\_  __ \/ __ |")
    print(r" |    |   \  ___// /_/ |   \        /|  |/    /  / __ \|  | \/ /_/ |")
    print(r" |____|_  /\___  >____ |    \__/\  / |__/_____ \(____  /__|  \____ |")
    print(r"        \/     \/     \/         \/           \/     \/           \/")
    print(r"")
    print(r"                     --- Creating inventory ---                     ")
    print(r"")

def main():
    """ Main function """
    print_ascii_art()
    parser = argparse.ArgumentParser(description="Creates the inventory for your Red Teaming campaign.\
                                                  This can either create a new one or modify\
                                                  an existing one.")

    parser.add_argument('directory', type=str, help='The target directory for the finished config')
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    hosts_yaml_location = os.path.join(options.directory, 'hosts.yml')
    if os.path.exists(hosts_yaml_location):
        confirmation = input(f"\nYou will modify the existing configuration in {hosts_yaml_location}. Continue? {BOLD_YELLOW} y/n{RESET}\n")
        if confirmation != 'Y' and confirmation != 'y':
            sys.exit(1)
        hosts_yaml = parse_yaml(hosts_yaml_location)
    else:
        hosts_yaml = {'backends' : {'hosts' : {}}, 'relays' : {'hosts' : {}}}
    initial_menu(hosts_yaml, hosts_yaml_location)


if __name__ == '__main__':
    main()
