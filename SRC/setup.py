#!/usr/bin/env python
# Copyright (C) 2017 stryngs.

from setuptools import setup

setup(
    name = 'packetEssentials',
    version = '1.6.2',
    author = 'stryngs',
    author_email = 'support@configitnow.com',
    packages = ['packetEssentials', 'packetEssentials.lib'],
    include_package_data = True,
    url = 'https://github.com/ICSec/packetEssentials',
    license ='GNU General Public License v2',
    keywords = '802.11 wifi ether scapy packet essentials',
    description='Essential nuances for Python Scapy revolving around packet hacking'
)
