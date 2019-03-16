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
        self.output_fmt = 'json'
        return

    def debug(self):
        if self.debug_enabled:
            return
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
        sort_method = ['id', 'DESC']

        while True:
            if page_cursor > 0:
                if page_cursor >= total_pages:
                    break
            api_response = api_instance.get_asset_groups(page=page_cursor, size=page_size, sort=sort_method)
            for resource in api_response.resources:
                item = {}
                item['id'] = resource.id
                item['name'] = resource.name
                item['type'] = resource.type
                if resource.description:
                    item['description'] = resource.description
                response['asset_groups'].append(item)
            total_pages = api_response.page.total_pages
            page_cursor += 1
        return response

    def get_tags(self):
        container = 'tags'
        response = {
            container: []
        }
        api_instance = py_insightvm_sdk.TagApi(self.api_client)
        page_cursor = 0
        total_pages = 0
        page_size = 1000
        sort_method = ['id', 'DESC']

        while True:
            if page_cursor > 0:
                if page_cursor >= total_pages:
                    break
            api_response = api_instance.get_tags(page=page_cursor, size=page_size, sort=sort_method)
            for resource in api_response.resources:
                item = {}
                item['id'] = resource.id
                item['name'] = resource.name
                item['type'] = resource.type
                if resource.source:
                    item['source'] = resource.source
                response[container].append(item)
            total_pages = api_response.page.total_pages
            page_cursor += 1
        return response


    def get_sites(self):
        container = 'sites'
        response = {
            container: []
        }
        api_instance = py_insightvm_sdk.SiteApi(self.api_client)
        page_cursor = 0
        total_pages = 0
        page_size = 1000
        sort_method = ['id', 'DESC']

        while True:
            if page_cursor > 0:
                if page_cursor >= total_pages:
                    break
            api_response = api_instance.get_sites(page=page_cursor, size=page_size, sort=sort_method)
            for resource in api_response.resources:
                item = {}
                item['assets'] = resource.assets
                item['connection_type'] = resource.connection_type
                item['description'] = resource.description
                item['id'] = resource.id
                item['importance'] = resource.importance
                item['last_scan_time'] = resource.last_scan_time
                item['name'] = resource.name
                item['risk_score'] = resource.risk_score
                item['scan_engine'] = resource.scan_engine
                item['scan_template'] = resource.scan_template
                item['type'] = resource.type
                response[container].append(item)
            total_pages = api_response.page.total_pages
            page_cursor += 1
        return response

    def get_vulnerabilities(self):
        return {'error': 'unsupported'}
        container = 'vulnerabilities'
        response = {
            container: []
        }
        api_instance = py_insightvm_sdk.VulnerabilityApi(self.api_client)
        page_cursor = 0
        total_pages = 0
        page_size = 1000
        sort_method = ['id', 'DESC']

        while True:
            if page_cursor > 0:
                if page_cursor >= total_pages:
                    break
            api_response = api_instance.get_vulnerabilities(page=page_cursor, size=page_size, sort=sort_method)
            for resource in api_response.resources:
                item = {}
                item['added'] = resource.added
                item['categories'] = resource.categories
                item['cves'] = resource.cves
                item['denial_of_service'] = resource.denial_of_service
                item['id'] = resource.id
                item['modified'] = resource.modified
                item['published'] = resource.published
                item['risk_score'] = resource.risk_score
                item['severity'] = resource.severity
                item['severity_score'] = resource.severity_score
                item['title'] = resource.title
                item['description_text']  = resource.description.text
                # skipped:
                # - VulnerabilityCvss
                response[container].append(item)
            total_pages = api_response.page.total_pages
            page_cursor += 1
        return response

    def get_assets(self):
        container = 'assets'
        response = {
            container: []
        }
        api_instance = py_insightvm_sdk.AssetApi(self.api_client)
        page_cursor = 0
        total_pages = 0
        page_size = 1000
        page_limit = 1000000
        sort_method = ['id', 'DESC']

        while True:
            if page_cursor > 0:
                if page_cursor >= total_pages:
                    break
                if page_cursor >= page_limit:
                    break
            api_response = api_instance.get_assets(page=page_cursor, size=page_size, sort=sort_method)
            for resource in api_response.resources:
                # Ommitted:
                # - configurations
                # - databases
                # - files
                # - history
                # - links
                # - os_fingerprint
                # - services
                # - software
                # - user_groups
                # - users
                # - vulnerabilities
                item = {}
                item['addresses'] = []
                if resource.addresses:
                    for addr in resource.addresses:
                        entry = {}
                        entry['ip_address'] = addr.ip
                        entry['mac_address'] = addr.mac
                        item['addresses'].append(entry)
                item['assessed_for_policies'] = resource.assessed_for_policies
                item['assessed_for_vulnerabilities'] = resource.assessed_for_vulnerabilities
                item['host_name'] = resource.host_name
                item['host_names'] = []
                if resource.host_names:
                    for host_name in resource.host_names:
                        entry = {}
                        entry['name'] = host_name.name
                        entry['source'] = host_name.source
                        item['host_names'].append(entry)
                item['id'] = resource.id
                item['ip'] = resource.ip
                item['ids'] = []
                if resource.ids:
                    for _id in resource.ids:
                        entry = {}
                        entry['id'] = _id.id
                        entry['source'] = _id.source
                        item['ids'].append(entry)
                item['mac'] = resource.mac
                item['os'] = resource.os
                item['raw_risk_score'] = resource.raw_risk_score
                item['risk_score'] = resource.risk_score
                item['type'] = resource.type
                response[container].append(item)
            total_pages = api_response.page.total_pages
            page_cursor += 1
        return response
