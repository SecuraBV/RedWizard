#!/usr/bin/python3
import os.path

import yaml


class BColors:
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
    Find the playbook and safely load the YAML
    """
    if not os.path.exists(filename):
        fix_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            filename
        )
        with open(fix_path, 'r') as stream:
            return yaml.safe_load(stream)
    with open(filename, 'r') as stream:
        return yaml.safe_load(stream)


def print_tags(tag_list):
    """
    Print and colorize tags
    """
    for tag in tag_list:
        print('\n' + BColors.OKGREEN + tag + BColors.ENDC + ":")
        for host in tag_list[tag]['hosts']:
            print(str(tag_list[tag]['hosts'][host]) + ' on ' + BColors.OKCYAN + host + BColors.ENDC)


def parse_plays(playbook_yaml):
    """
    Parse the entries from the playbook file
    """
    tag_list = {}
    for item in playbook_yaml:
        for tag in item['tags']:
            if tag not in tag_list:
                tag_list[tag] = {}
                tag_list[tag]['hosts'] = {}
            tag_list[tag]['hosts'][item['hosts']] = item['roles']
    return tag_list


def main():
    """
    Start the playbook parsing
    """
    playbook_yaml = parse_yaml("playbook.yml")
    tag_list = parse_plays(playbook_yaml)
    print_tags(tag_list)


if __name__ == '__main__':
    main()
