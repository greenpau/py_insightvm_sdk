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

# python 2 and python 3 compatibility library
import six
from six.moves.urllib.parse import quote

import py_insightvm_sdk
from py_insightvm_sdk.rest import ApiException
from py_insightvm_sdk.models import Configuration
from py_insightvm_sdk.app_configuration import AppConfiguration
#import httplib
#httplib.HTTPConnection.debuglevel=5
import urllib3
urllib3.disable_warnings()

class AppClient(object):
    '''
    This class implements the client application.
    '''

    def __init__(self):
        ''' Initializes the class. '''
        self.log = logging.getLogger('ivm-client')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(name)s@%(lineno)d: %(message)s')
        handler.setFormatter(formatter)
        self.log.addHandler(handler)
        self.debug_enabled = False
        self.config = AppConfiguration()
        self.config.load()
        self.api_configuration = Configuration('default')
        self.api_configuration.verify_ssl = False
        self.api_configuration.ssl_ca_cert = False
        self.api_configuration.assert_hostname = None
        self.api_configuration.connection_pool_maxsize = 4
        self.api_configuration.proxy = None
        self.api_configuration.cert_file = None
        self.api_configuration.key_file = None
        self.api_configuration.host = '%s://%s:%s' % (
            self.config.settings['protocol'],
            self.config.settings['host'],
            self.config.settings['port'],
        )
        self.api_client = py_insightvm_sdk.ApiClient(
            configuration = self.api_configuration,
            header_name='Authorization',
            header_value=self.config.get_authorization_value(),
        )
        return

    def debug(self):
        if not self.debug_enabled:
            import httplib
            httplib.HTTPConnection.debuglevel=5
        self.log.setLevel(logging.DEBUG)
        self.debug_enabled = True
        self.config.log.setLevel(logging.DEBUG)
        self.config.debug_enabled = True
        return

    def get_asset_groups(self):
        response = {
            'asset_groups': []
        }
        api_instance = py_insightvm_sdk.AssetGroupApi(self.api_client)
        page_cursor = 0
        page_size = 1000
        sort_method = []
        api_response = api_instance.get_asset_groups(page=page_cursor, size=page_size, sort=sort_method)
        for resource in api_response.resources:
            item = {}
            item['id'] = resource.id
            item['name'] = resource.name
            item['type'] = resource.type
            if resource.description:
                item['description'] = resource.description
            response['asset_groups'].append(item)
        return response
