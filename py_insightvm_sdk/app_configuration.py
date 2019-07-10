#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copyright (C) 2019 Paul Greenberg @greenpau
See LICENSE for licensing details
'''

from __future__ import (absolute_import, division, print_function)
import os
import stat
import logging
import ConfigParser
import base64

class AppConfiguration(object):
    '''
    This class implements the client application configuration.
    '''

    def __init__(self, cfg_file=None):
        ''' Initializes the class. '''
        self.cfg_file = cfg_file
        self.settings = {}
        self.log = logging.getLogger('ivm-config')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(name)s@%(lineno)d: %(message)s')
        handler.setFormatter(formatter)
        self.log.addHandler(handler)
        self.debug_enabled = False
        self.cfg_key_pairs = [
            'credentials:username',
            'credentials:password',
            'manager:host',
            'manager:port',
            'manager:protocol',
            'manager:basepath'
        ]
        self.env_key_pairs = [
            ('RAPID7_IVM_USER', 'username'),
            ('RAPID7_IVM_PWD', 'password'),
            ('RAPID7_IVM_HOST', 'host'),
            ('RAPID7_IVM_PORT', 'port'),
            ('RAPID7_IVM_PROTO', 'protocol'),
            ('RAPID7_IVM_BASEPATH', 'basepath'),
        ]
        self.load()
        return

    def load(self, cfg_file=None):
        ''' Load configuration from a configuration file in RC format. '''
        if not cfg_file:
            cfg_file = self.cfg_file
        if not cfg_file:
            cfg_file = os.path.expanduser('~/.py_insightvm_sdk.rc')
        self.log.debug('configuration file: %s', cfg_file)

        _has_cfg_file = True
        if not os.path.exists(cfg_file):
            self.log.debug('configuration file: %s does not exist ', cfg_file)
            _has_cfg_file = False

        ''' Validate configuration file permissions '''
        if _has_cfg_file:
            cfg_file_stat = os.stat(cfg_file)
            if cfg_file_stat.st_mode & stat.S_IROTH:
                raise Exception('config', 'configuration file %s is world readable' % cfg_file)
            if cfg_file_stat.st_mode & stat.S_IRGRP:
                raise Exception('config', 'configuration file %s is group readable' % cfg_file)

        ''' Handle configuration file '''
        if _has_cfg_file:
            self.cfg_file = cfg_file
            cfg_parser = ConfigParser.RawConfigParser()
            cfg_parser.read(cfg_file)
            for cfg_key_pair in self.cfg_key_pairs:
                cfg_section, cfg_key = cfg_key_pair.split(':')
                if cfg_section not in cfg_parser.sections():
                    self.log.debug('configuration file ' + \
                            '%s has no %s section', cfg_file, cfg_section)
                    continue
                if cfg_parser.has_option(cfg_section, cfg_key):
                    self.settings[cfg_key] = cfg_parser.get(cfg_section, cfg_key)

        ''' Handle environment variables '''
        for env_key_pair in self.env_key_pairs:
            if not os.environ.get(env_key_pair[0]):
                continue
            self.settings[env_key_pair[1]] = os.environ.get(env_key_pair[0])

        self.validate()
        return

    def validate(self):
        '''
        Validates that all configuration parameters necessary to establish
        a connection to SEP Manager are present.
        '''
        for cfg_key_pair in self.cfg_key_pairs:
            cfg_section, cfg_key = cfg_key_pair.split(':')
            if cfg_key not in self.settings:
                if cfg_key == 'protocol':
                    self.settings[cfg_key] = 'https'
                elif cfg_key == 'port':
                    self.settings[cfg_key] = '443'
                elif cfg_key == 'basepath':
                    self.settings[cfg_key] = 'api/3'
                elif cfg_key == 'host':
                    self.settings[cfg_key] = 'localhost'
                else:
                    raise Exception('config', \
                            "no '%s' key in '%s' " % (cfg_key, cfg_section) + \
                            "section of the configuration")
            else:
                self.settings[cfg_key] = self.settings[cfg_key].strip("'").strip('"')
        return

    def get(self, item='url'):
        ''' Return configuration settings. '''
        if item == 'url':
            return '%s://%s:%s/%s' % (self.settings['protocol'], self.settings['host'], \
                    self.settings['port'], self.settings['basepath'])
        elif item == 'username':
            return '%s' % (self.settings['username'])
        else:
            if item in self.settings:
                return '%s' % (self.settings[item])
        return None

    def get_authorization_value(self):
        for k in ['username', 'password']:
            if k not in self.settings:
                return None
        return 'Basic ' + base64.b64encode('%s:%s' % (self.settings['username'], self.settings['password']))
