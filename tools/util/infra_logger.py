#!/usr/bin/env python3
# encoding: utf-8

"""
This module provides generic logging functionality for the infra deployment
Use in your submodule in the following fashion:

from infra_logger import initiate_logger
logger = initiate_logger()
logger.error("MESSAGE")
"""

import logging
import os
from pathlib import Path

# set pwd to current working directory
PWD = Path(os.getcwd())

class CustomFormatter(logging.Formatter):
    """ Initiates the custom format for our log messages"""
    bold_grey = "\x1b[38;1m"
    bold_yellow = "\x1b[33;1m"
    bold_magenta = "\x1b[35;1m"
    bold_red = "\x1b[31;1m"
    bold_cyan = "\x1b[36;1m"
    reset = "\x1b[0m"
    message_format = "(%(filename)s) %(message)s"

    FORMATS = {
        logging.DEBUG: f"{bold_grey}DEBUG:{reset} {message_format}",
        logging.INFO: f"{bold_cyan}INFO:{reset} {message_format}",
        logging.WARNING: f"{bold_yellow}WARNING:{reset} {message_format}",
        logging.ERROR: f"{bold_red}ERROR:{reset} {message_format}",
        logging.CRITICAL: f"{bold_magenta}CRITICAL:{reset} {message_format}"
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def initiate_logger(name):
    "Initiates the logger. This should be called by the submodule"

    # create logger with the name of the module calling it
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # create console handler with a higher log level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(CustomFormatter())
    logger.addHandler(console_handler)

    return logger
