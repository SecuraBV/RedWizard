#!/usr/bin/env python3
"""
This Python script creates an initial configuration file based on global settings
Please make sure your globals.yml file has all the required options set
"""
import getpass
import optparse
import os
import subprocess
import sys
import logging
import string
import random
import crypt
from colorama import Fore, Style

import validators.email
import yaml
from IPy import IP
from ansible_vault import Vault
import ansible
from tools.util.jinja_templating import get_jinja_env

###############################################################################
# Constants
###############################################################################

# Jinja2 Templating is used to create the hosts file
CONFIGURATION_TEMPLATE = 'configuration.yml'

###############################################################################
# IO Functions to read and write yaml files
###############################################################################

def write_template(out_file, output):
    """ Writes the completed template to the designated outfile """
    try:
        with open(out_file, 'w') as file_handler:
            file_handler.truncate()  # Clear the files before we start
            file_handler.write(output)
            logging.info("Saved configuration")
    except FileNotFoundError:
        logging.critical("Unable to write to %s" % str(out_file))
        raise
    except OSError as os_error:
        logging.critical(f"Error opening file: {os_error:}")
        raise

def pretty_print(yml_dict, key):
    """ Pretty prints a dictionary into predefined yaml format """
    try:
        toplevel = {key : yml_dict[key]}
        return yaml.dump(toplevel, width=80, indent=4, default_flow_style=False)
    except KeyError:
        return ""

def create_configuration_template(out_file, configuration_set):
    """ Sets all the neccesary variables to print the jinja2 template """
    for key in configuration_set.keys():
        configuration_set[key] = pretty_print(configuration_set, key)

    jinja_env = get_jinja_env()
    template = jinja_env.get_template(CONFIGURATION_TEMPLATE)

    output = template.render(configuration_set)

    write_template(out_file, output)

def open_globals(options):
    """
    Opens and extracts information from the global configuration file
    """
    logging.info("Using template: %s", options.template)
    document = None
    try:
        question = "Enter the password for the template %s (installation default is " + Fore.GREEN + "'ansible'"+Style.RESET_ALL+ "):"
        password = getpass.getpass(question % options.template)
        if password == "":
            password = "ansible"
        vault = Vault(password=password)
        document = vault.load(open(options.template).read())
        return document

    except OSError as e:
        logging.critical(
            "There was an error reading the global configuration file: %s", e
        )
    except ansible.parsing.vault.AnsibleVaultError as e:
        logging.critical(
            "Error decrypting vault: %s", e
        )
        sys.exit(1)

###############################################################################
# Input Validation functions
###############################################################################

def validate_net(input_addr):
    """
    Validate an input IP address or range
    """
    if isinstance(input_addr, list):
        for entry in input_addr:
            result = validate_net(entry)
            if not result:
                return False
        return True
    else:
        try:
            IP(input_addr)
            return True
        except Exception as e:
            logging.warning("%s does not look like a valid IP address or range", input_addr)
            return False

###############################################################################
# Support Functions
###############################################################################

def random_secret(length=24, pool=None):
    """
    Generate a random string with x length
    """
    if not pool:
        pool = string.ascii_lowercase + string.ascii_uppercase + string.digits
    out = ""
    for _ in range(length):
        out += random.choice(pool)
    return out


def request_input(prompt, default=None, as_boolean=False):
    """
    Prompt a user for input
    """
    while 1:
        if default:
            default_text = Fore.GREEN + f"{default}" + Style.RESET_ALL
            selection = input(
                f"{prompt} - default {default_text} (or x to exit): "
            )
            if selection and selection == "x":
                sys.exit(0)
            if not selection.strip():
                if as_boolean:
                    return "y" in default.lower()
                return default
            if selection:
                return selection
        else:
            selection = input(
                f"{prompt} (or x to exit): "
            )
            if selection and selection == "x":
                sys.exit(0)
            if selection.strip():
                if as_boolean:
                    return "y" in selection.lower()
                return selection
        logging.warning("Invalid input!")


def create_configuration_directory(options):
    """
    Create a new configuration directory
    """
    new_dir = options.confdir
    if not new_dir:
        new_dir = request_input(
            prompt="Enter directory name for new configuration"
        )
    fullpath_magic = os.path.join(
        os.path.dirname(__file__),
        new_dir
    )
    if os.path.exists(fullpath_magic):
        still_deploy = request_input(
            "\nDirectory already exists, do you still want to use this directory? [Ny]",
            default="n",
        )
        print("")
        if not still_deploy == 'y':
            logging.info("\nDirectory already exists, exiting..")
            sys.exit(-1)

    else:
        logging.info(f"Creating directory {fullpath_magic}")
        os.mkdir(fullpath_magic)
    return fullpath_magic


def request_email_entries_phishing(options, document, ignore_options=False):
    """
    Ask a user to input a valid email address
    """
    phishing_reply_to = None
    if not ignore_options:
        phishing_reply_to = options.phishing_reply_to
    if not phishing_reply_to:
        phishing_reply_to = request_input(
            "Please enter a mail address to receive phishing replies",
            default=document['phishing_reply_forwards']
        )
    if validators.email(phishing_reply_to):
        return phishing_reply_to
    logging.warning("An invalid email address was supplied, please try again.")
    return request_email_entries_phishing(options, document, ignore_options=True)


def request_email_entries_certbot(options, document, ignore_options=False):
    """
    Ask a user to input a valid email address
    """
    phishing_reply_to = None
    if not ignore_options:
        phishing_reply_to = options.certbot_email
    if not phishing_reply_to:
        phishing_reply_to = request_input(
            "\nPlease enter a mail address to request a LetsEncrypt certificate",
            default=document['certbot_mail_address']
        )
    if validators.email(phishing_reply_to):
        return phishing_reply_to
    logging.warning("An invalid email address was supplied, please try again.")
    return request_email_entries_certbot(options, document, ignore_options=True)


def do_interactive_edit(document):
    """
    Interactive dictionary editor
    """
    while 1:
        print("")
        print("==== Current variables ====")
        max_key = max(map(len, (map(str, document.keys()))))
        max_val = 120 - max_key
        for key in document:
            if key == "users":
                userlist =  ",".join(document[key].keys())
                print('- {:<{}}    {:<{}}'.format(str(key), max_key, userlist, max_val))
            else:
                print('- {:<{}}    {:<{}}'.format(str(key), max_key, str(document[key]), max_val))
        print("")
        print("The following commands are available:")
        print(" - [s]et [name] [value] (array entries can be entered using a comma)")
        print(" - [u]nset [name] (remove a variable from the configuration)")
        print(" - [c]ontinue (deploy the current configuration)")
        do_action = input("Action: ")
        if not do_action:
            logging.warning("Invalid option: %s", do_action)
            continue
        if do_action.startswith("c"):
            break
        if do_action.startswith("u"):
            _, to_unset = do_action.split(" ")
            if to_unset in document:
                del document[to_unset]
            else:
                print(f"Invalid key: {to_unset}")
        if do_action.startswith("s"):
            variables = do_action.split(" ")
            key = variables[1]
            new_value = " ".join(variables[2:]).strip()
            if "," in new_value:
                new_value = [x.strip() for x in new_value.split(",")]
            document[key] = new_value
    return document


def prepare_users(users, options, conf_dir):
    """
    Create user account options if not set
    """
    if not users:
        return users
    out_users = {}
    for user in users:
        data = users[user]
        if data['sshkey'] == "XXX":
            data['sshkey'] = ssh_keygen(
                project_path=conf_dir,
                options=options,
                username=data['username']
            )
        if data['pwhash'] == "XXX":
            data['pwhash'] = crypt.crypt(
                getpass.getpass(
                    f"Please enter a password for user {user}: "
                ),
                crypt.mksalt(crypt.METHOD_SHA512)
            )
        out_users[user] = data

    return out_users


def add_users_to_deployment(users, options):
    """
    Verify and select a list of users with access to this infrastructure deployment
    """
    available_users = [name for name in users]
    output_users = dict()
    if not available_users:
        logging.critical("No user credentials are configured in the globals.yml configuration")
        sys.exit(1)
    if available_users == ["corpuser"]:
        logging.warning("No custom user credentials are configured in the globals.yml configuration")
    selected_users = options.users
    if not selected_users:
        question = "\nAvailable users: "+Fore.GREEN+"%s"+Style.RESET_ALL
        print(question % ', '.join(available_users))
        selected_users = request_input(
            "Please enter a comma separated list of users (or all for all users)"
        )
    if selected_users.strip() == "all":
        return users
    selected_users = [user.strip() for user in selected_users.split(",")]
    for selected in selected_users:
        if selected not in available_users:
            logging.warning("User %s does not exist in the configuration and will be ignored", selected)
        else:
            output_users[selected] = users[selected]
    return output_users


def run_globals(options):
    """
    Verify existing parameters and apply some changes
    """
    document = open_globals(options)
    logging.debug("Validating IP addresses and ranges")
    ip_ranges = [
        "company_ip_space", "company_c2_space", "internal_vpn_ip_space",
        "internal_vpn_ip_gateway"
    ]
    for ip_check in ip_ranges:
        fetch = document[ip_check]
        is_ok = validate_net(fetch)
        if not is_ok:
            logging.critical(
                "%s contains an invalid value", ip_check
            )
            sys.exit(1)
    document['certbot_mail_address'] = request_email_entries_certbot(
        options=options,
        document=document,
        ignore_options=False
    )
    document['phishing_reply_forwards'] = request_email_entries_phishing(
        options=options,
        document=document,
        ignore_options=False
    )
    if options.codename:
        document['codename'] = options.codename.strip()
    else:
        document['codename'] = request_input(
            "Enter a codename for this deployment (Alphanumeric, no spaces)",
            default="DEVELOPMENT"
        )
    if options.ansible_user:
        document['ansible_user'] = options.ansible_user.strip()
    else:
        document['ansible_user'] = request_input(
            "Enter the username that Ansible can use to connect with SSH",
            default="ubu"
        )
    if not document['ansible_user']:
        logging.critical(
            "Ansible deployment requires access to a SSH account on the remote machine."
        )
        sys.exit(1)
    document['users'] = add_users_to_deployment(document['users'], options)
    if not options.no_interactive:
        document = do_interactive_edit(document)
    return document


def ansible_keygen(conf_dir, options):
    """
    Create default accounts and deploy vault
    """
    get_existing = os.path.join(
        conf_dir,
        options.vault
    )

    if not os.path.exists(get_existing):
        password = getpass.getpass("\nEnter the "+Fore.GREEN+"new"+Style.RESET_ALL+" Ansible vault password (For the new local configuration): ")
        try:
            vault = Vault(password=password)
        except ValueError:
            logging.critical(
                "No password for vault was entered, exiting"
            )
            sys.exit(1)

        set_vars = dict()
        if options.autogen:
            set_vars['ansible_become_pass'] = random_secret()
            set_vars['gophish_password'] = random_secret()
            set_vars['cobaltstrike_password'] = random_secret()

            print("Autogenerated the following secrets:")
            for var in set_vars:
                print(f"{var} => {set_vars[var]}")
            set_vars['cs_license'] = getpass.getpass(
                prompt="Please enter your CobaltStrike license key for deployment" + Fore.GREEN + " (leave empty if not needed)"+Style.RESET_ALL+ ": "
            )
            if set_vars['cs_license'] == "":
                password = "No license key provided"
        else:
            set_vars['ansible_become_pass'] = getpass.getpass(
                prompt="Please enter the ansible "+Fore.GREEN+"sudo"+Style.RESET_ALL+" password: "
            )
            set_vars['gophish_password'] = getpass.getpass(
                prompt="Please enter a password for your "+Fore.GREEN+"GoPhish"+Style.RESET_ALL+" deployment: "
            )
            set_vars['cobaltstrike_password'] = getpass.getpass(
                prompt="Please enter a password for your "+Fore.GREEN+"CobaltStrike"+Style.RESET_ALL+" deployment: "
            )
            set_vars['cs_license'] = getpass.getpass(
                prompt="Please enter your CobaltStrike "+Fore.GREEN+"license key"+Style.RESET_ALL+" for deployment  (leave empty if not needed): "
            )
            if set_vars['cs_license'] == "":
                password = "No license key provided"

        with open(get_existing, "w") as load_vault:
            logging.info("Saving variables to new vault: %s", get_existing)
            vault.dump(set_vars, load_vault)
    else:
        logging.info("Vault %s already exists, not creating again", get_existing)
        return True


def ssh_keygen(options, project_path, username):
    """
    Create a new SSH key for a user and return public key
    """
    get_cert_directory = os.path.join(project_path, "ssh-keys")
    if not os.path.exists(get_cert_directory):
        logging.debug("Creating ssh key directory")
        os.mkdir(get_cert_directory)
    output_file = os.path.join(
        get_cert_directory,
        f"id_{username}"
    )
    if os.path.exists(output_file):
        logging.warning("SSH key for user %s already exists, returning public key", username)
    else:
        logging.info("Creating new SSH key for user %s", username)
        run_arguments = [
            "ssh-keygen",
            "-f",
            output_file
        ]
        if options.ssh_passwd:
            if len(options.ssh_passwd) < 5:
                logging.warning("ssh-keygen requires at least a 5 character key, ignoring user")
                return None
            run_arguments.extend([
                "-P", options.ssh_passwd
            ])
        else:
            new_pass = getpass.getpass(
                prompt=f"Please enter a password for private key {output_file}: "
            )
            run_arguments.extend([
                "-P", new_pass
            ])
            if len(new_pass) < 5:
                logging.warning("ssh-keygen requires at least a 5 character key, ignoring user")
                return None
        subprocess.run(run_arguments)
    get_pubkey = os.path.join(
        get_cert_directory,
        f"id_{username}.pub"
    )
    if os.path.exists(get_pubkey):
        os.chmod(output_file, 0o600)
        with open(get_pubkey, 'r') as read_pubkey:
            return read_pubkey.read().strip()
    return None

def set_logging(options):
    logging.basicConfig(stream=sys.stdout, level=logging.WARNING if options.silent else logging.DEBUG)
    try:
        import coloredlogs
        coloredlogs.install(fmt='- %(asctime)s - %(message)s', level=logging.WARNING if options.silent else logging.DEBUG)
    except ImportError:
        pass

def parse_options():
    parser = optparse.OptionParser(
        description="This Python script creates an initial configuration file based on global settings, "
                    "Please make sure your globals.yml file has all the required options set.")
    default_group = optparse.OptionGroup(
        parser=parser, title="Default",
        description="Required variables for automated deployment (otherwise user will be prompted)"
    )
    default_group.add_option("-c", "--conf-dir", dest="confdir",
                             help="The new configuration directory", default=None)
    default_group.add_option("-n", "--codename", dest="codename",
                             help="Codename of the new deployment", default=None)
    default_group.add_option("-t", "--template",
                             dest="template", default="globals.yml",
                             help="The global variable template to use")
    default_group.add_option("-v", "--vault",
                             dest="vault", default="vaulted_vars.yml",
                             help="The ansible vault to use (default: create if not exist)")
    default_group.add_option("--autogenerate", dest="autogen",
                             default=False, action="store_true",
                             help="Automatically generate deployment passwords during configuration")

    configuration_group = optparse.OptionGroup(
        parser=parser, title="Configuration",
        description="Common configuration options for module specific deployment")

    configuration_group.add_option("--ansible-user",
                                   dest="ansible_user", default=None,
                                   help="Username that ansible can use to access machines for deployment")

    configuration_group.add_option("-u", "--users",
                                   dest="users", default=None,
                                   help="Comma separated list of allowed users (all to add all available users)")
    configuration_group.add_option("-P", "--ssh-password",
                                   dest="ssh_passwd", default=None,
                                   help="Set a default password when creating new SSH keys (default: prompt) "
                                        "Note: ssh-keygen requires at least 5 characters!")
    configuration_group.add_option("--certbot-email",
                                   dest="certbot_email", default=None,
                                   help="Use this email to request LetsEncrypt certificates")
    configuration_group.add_option("--phishing-reply-to",
                                   dest="phishing_reply_to", default=None,
                                   help="Use this email receive replies on phishing mails")

    misc_options = optparse.OptionGroup(
        parser=parser, title="Misc options",
        description="Some miscellaneous deployment options"
    )
    misc_options.add_option("--no-interactive",
                            dest="no_interactive", default=False, action="store_true",
                            help="Do not run the interactive configuration editor")
    misc_options.add_option("-q", "--silent",
                            dest="silent", default=False, action="store_true",
                            help="Only print errors and warnings")
    parser.add_option_group(default_group)
    parser.add_option_group(configuration_group)
    parser.add_option_group(misc_options)
    (options, _) = parser.parse_args()
    return options

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
    print(r"                      ---  Config Creation ---                      ")
    print(r"")

def main():
    """ The main function for configuration deployment  """
    options = parse_options()
    print_ascii_art()
    set_logging(options)
    conf_dir = create_configuration_directory(options)
    output_configuration = run_globals(options)
    output_configuration['users'] = prepare_users(
        output_configuration['users'],
        options,
        conf_dir
    )
    output_file = os.path.join(conf_dir, "configuration.yml")
    ansible_keygen(conf_dir=conf_dir, options=options)
    logging.info("Saving final configuration to %s", output_file)
    create_configuration_template(output_file, output_configuration)

if __name__ == "__main__":
    main()
