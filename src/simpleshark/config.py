import os

import py

import simpleshark

CONFIG_PATH = os.path.join(os.path.dirname(simpleshark.__file__), 'config.ini')


def get_config():
    return py.iniconfig.IniConfig(CONFIG_PATH)
