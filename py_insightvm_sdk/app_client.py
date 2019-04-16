#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copyright (C) 2019 Paul Greenberg @greenpau
See LICENSE for licensing details
'''

from __future__ import (absolute_import, division, print_function)
import os
import stat
import re
import json
import yaml
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
        self.api_configuration.safe_chars_for_path_param = ''
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

    def get_vulnerabilities(self, opts={}):
        container = 'vulnerabilities'
        response = {
            container: []
        }
        api_instance = py_insightvm_sdk.VulnerabilityApi(self.api_client)
        page_cursor = 0
        total_pages = 0
        page_size = 1000
        page_limit = 1000000
        if 'page_size' in opts:
            page_size = opts['page_size']
        if 'page_limit' in opts:
            page_limit = opts['page_limit']
        sort_method = ['id', 'DESC']

        while True:
            if page_cursor > 0:
                if page_cursor >= total_pages:
                    break
                if page_cursor >= page_limit:
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

    def get_assets(self, opts={}):
        container = 'assets'
        response = {
            container: []
        }
        api_instance = py_insightvm_sdk.AssetApi(self.api_client)
        page_cursor = 0
        total_pages = 0
        page_size = 1000
        page_limit = 1000000
        if 'page_size' in opts:
            page_size = opts['page_size']
        if 'page_limit' in opts:
            page_limit = opts['page_limit']
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
                if resource.host_name:
                    item['hostname'] = resource.host_name.lower()
                item['hostnames'] = []
                if resource.host_names:
                    for host_name in resource.host_names:
                        entry = {}
                        entry['name'] = host_name.name
                        entry['source'] = host_name.source
                        item['hostnames'].append(entry)
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
                if 'with_vulnerabilities' in opts:
                    item['vulnerabilities'] = resource.vulnerabilities.__dict__
                response[container].append(item)
            total_pages = api_response.page.total_pages
            page_cursor += 1
        return response

    def get_high_risk_asset_ids(self, asset_file, opts={}):
        from operator import itemgetter
        container = 'assets'
        response = {
            container: []
        }
        data = None
        asset_ids = []
        self.log.debug('asset reference file name: %s' % (asset_file.name))
        if re.search('\.y[a]?ml$', asset_file.name):
            data = yaml.load(asset_file)
        else:
            data = json.load(asset_file)
        self.log.debug('loaded assets from: %s' % (asset_file.name))
        # From high to low
        assets = sorted(data['assets'], key=itemgetter('risk_score'), reverse=True)
        # From low to high
        #assets = sorted(data['assets'], key=itemgetter('risk_score'))
        limit = 2
        if 'limit' in opts:
            limit = opts['limit']
        if len(assets) > limit:
            assets = assets[:limit]

        if self.output_fmt == 'csv':
            lines = []
            for asset in assets:
                line = []
                line.append(str(asset['id']))
                line.append(str(asset['risk_score']))
                if 'hostname' in asset:
                    line.append(asset['hostname'])
                else:
                    line.append(asset['ip'])
                line.append(asset['ip'])
                lines.append(';'.join(line))
            return '\n'.join(lines) + '\n' 

        response[container] = assets
        return response

    def get_assets_from_file(self, asset_file, asset_filters=None):
        container = 'assets'
        response = {
            container: []
        }
        _filter = None
        for asset_filter in asset_filters:
            _valid_filter = False
            for k in ['name', 'ip']:
                if not asset_filter.startswith(k + ':'):
                    continue
                _valid_filter = True
                if not _filter:
                    _filter = {}
                if k not in _filter:
                    _filter[k] = []
                _value = asset_filter.split(':')[1].lower()
                _filter[k].append(_value)
            if not _valid_filter:
                raise Exception('get_assets_from_file', 'invalid filter: %s' % (asset_filter))
        data = None
        asset_ids = []
        self.log.debug('asset reference file name: %s' % (asset_file.name))
        if re.search('\.y[a]?ml$', asset_file.name):
            data = yaml.load(asset_file)
        else:
            data = json.load(asset_file)
        self.log.debug('loaded assets from: %s' % (asset_file.name))
        assets = data['assets']
        for asset in assets:
            _continue = True
            for k in ['name', 'ip']:
                if k not in _filter:
                    continue
                for f in _filter[k]:
                    if k == 'name' and 'hostname' in asset:
                        if re.search(f, asset['hostname']):
                            _continue = False
                    elif k == 'ip':
                        if f == asset['ip']:
                            _continue = False
                    else:
                        pass
            if _continue:
                continue
            asset_ids.append(asset['id'])
        #return response
        return asset_ids

    def get_asset_by_id(self, asset_id=None):
        api_instance = py_insightvm_sdk.AssetApi(self.api_client)
        api_response = api_instance.get_asset(id=asset_id)
        response = None
        if self.output_fmt == 'csv':
            response = {}
        else:
            response = yaml.load('%s' % (api_response))
        if 'vulnerabilities' in response:
            response['vulnerabilities_total'] = response['vulnerabilities'].copy()
        response['vulnerabilities'] = self.get_vulnerability_ids_by_asset_id(asset_id)
        return response


    def get_vulnerability_ids_by_asset_id(self, asset_id=None):
        response = []
        api_instance = py_insightvm_sdk.VulnerabilityResultApi(self.api_client)
        page_cursor = 0
        total_pages = 0
        page_size = 1000
        sort_method = ['id', 'DESC']

        while True:
            if page_cursor > 0:
                if page_cursor >= total_pages:
                    break
            api_response = api_instance.get_asset_vulnerabilities(asset_id, page=page_cursor, size=page_size, sort=sort_method)
            for resource in api_response.resources:
                item = {}
                item['id'] = resource.id
                item['since'] = resource.since
                item['status'] = resource.status
                response.append(item)
            total_pages = api_response.page.total_pages
            page_cursor += 1

        new_response = []
        api_instance = py_insightvm_sdk.VulnerabilityApi(self.api_client)
        for entry in response:
            try:
                api_response = api_instance.get_vulnerability(entry['id'])
                data = yaml.load('%s' % (api_response))
                for k in data:
                    entry[k] = data[k]
            except:
                pass
            new_response.append(entry)

        return new_response


    def get_asset_data_from_file(self, asset_file, data_category):
        data = None
        output = []
        self.log.debug('asset reference file name: %s' % (asset_file.name))
        if re.search('\.y[a]?ml$', asset_file.name):
            data = yaml.load(asset_file)
        else:
            data = json.load(asset_file)
        container = None
        headers = None
        if data_category == 'vulnerabilities':
            data = data['vulnerabilities']
            headers = ['id', 'title', 'published']
        elif data_category == 'services':
            data = data['services']
            headers = ['protocol', 'port', 'name', 'product']
        elif data_category == 'software':
            data = data['software']
            headers = ['vendor', 'description', 'version']
        else:
            return 'None\n'

        for item in data:

            line = []
            for header in headers:
                if header in item:
                    if item[header] == 'None':
                       line.append('')
                       continue
                    line.append(str(item[header]))
                else:
                    line.append('')
            output.append(';'.join(line))
            
        return '\n'.join(output) + '\n'
