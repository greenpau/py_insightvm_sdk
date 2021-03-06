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
import csv
from datetime import datetime
from copy import deepcopy
from io import BytesIO as StringIO

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
        self.vuln_ref_dir = None
        return

    def debug(self):
        if self.debug_enabled:
            return
        self.log.setLevel(logging.DEBUG)
        self.debug_enabled = True
        self.config.log.setLevel(logging.DEBUG)
        self.config.debug_enabled = True
        return

    def set_vuln_ref_dir(self, fp=None):
        if not fp:
            return
        if not os.path.isdir(fp):
            raise Exception('set_vuln_ref_dir', 'invalid path: %s' % (fp))
        if not os.access(fp, os.R_OK):
            raise Exception('set_vuln_ref_dir', 'path  is not readable: %s' % (fp))
        self.vuln_ref_dir = fp

    def get_asset_groups(self, opts={}):
        container = 'asset_groups'
        response = {
            container: []
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
                response[container].append(item)
            total_pages = api_response.page.total_pages
            page_cursor += 1
        if 'without_header' in opts:
            return response[container]
        return response

    def get_tags(self, opts={}):
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
        if 'without_header' in opts:
            return response[container]
        return response


    def get_sites(self, opts={}):
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
        if 'without_header' in opts:
            return response[container]
        return response


    def get_scans(self, opts={'delimeter': ';'}):
        container = 'scans'
        is_running_only = False
        if 'is_running_only' in opts:
            is_running_only = opts['is_running_only']
        required_fields = [
            'duration', 'end_time', 'engine_id', 'engine_name',
            'message', 'scan_name', 'scan_type', 'start_time', 'started_by',
            'status', 'site_name'
        ]
        response = {
            container: []
        }
        items = []
        api_instance = py_insightvm_sdk.ScanApi(self.api_client)
        page_cursor = 0
        total_pages = 0
        page_size = 500
        sort_method = ['id', 'DESC']

        while True:
            if page_cursor > 0:
                if page_cursor >= total_pages:
                    break
            api_response = api_instance.get_scans(active=is_running_only, page=page_cursor, size=page_size, sort=sort_method)
            for resource in api_response.resources:
                item = {}
                item['assets'] = resource.assets
                for k in ['assets', 'id', 'site_id', 'vulnerabilities']:
                    item[k] = getattr(resource, k, None)
                for k in required_fields:
                    item[k] = str(getattr(resource, k, 'None'))
                for link in resource.links:
                    if 'links' not in item:
                        item['links'] = []
                    item['links'].append(link.href)
                item['vulnerabilities'] = {}
                for k in ['critical', 'moderate', 'severe', 'total']:
                    item['vulnerabilities'][k] =  getattr(resource.vulnerabilities, k, 0)
                if item['scan_type'] == 'Agent':
                    continue
                items.append(item)
            total_pages = api_response.page.total_pages
            page_cursor += 1

        if self.output_fmt == 'csv':
            local_memory = StringIO()
            csv_writer = csv.writer(local_memory)
            required_fields = [
                'id', 'start_time', 'end_time', 'duration', 'assets', 'engine_id',
                'engine_name', 'site_name', 'scan_name', 'scan_type', 'message',
                'status', 'started_by'
            ]
            csv_headers = deepcopy(required_fields)
            for k in ['total', 'moderate', 'severe', 'critical']:
                csv_headers.append(k + '_vulnerabilities')
            if 'without_header' not in opts:
                csv_writer.writerow(csv_headers)
            for item in items:
                line = []
                for k in required_fields:
                    line.append(item[k])
                for k in ['total', 'moderate', 'severe', 'critical']:
                    line.append(item['vulnerabilities'][k])
                csv_writer.writerow(line)
            csv_data = local_memory.getvalue()
            local_memory.close()
            return csv_data

        response[container] = items
        if 'without_header' in opts:
            return response[container]
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
        if 'limit' in opts:
            page_limit = 1
            page_size = opts['limit']
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
                    vulnerabilities = resource.vulnerabilities.__dict__
                    item['vulnerabilities_total'] = {}
                    for v in vulnerabilities:
                        if v.startswith('_'):
                            item['vulnerabilities_total'][v.lstrip('_')] = vulnerabilities[v]
                response[container].append(item)
            total_pages = api_response.page.total_pages
            page_cursor += 1
        if 'without_header' in opts:
            return response[container]
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

    def get_asset_by_id(self, asset_id=None, opts={}):
        api_instance = py_insightvm_sdk.AssetApi(self.api_client)
        api_response = api_instance.get_asset(id=asset_id)
        response = None
        if self.output_fmt == 'csv':
            response = {}
        else:
            data = '%s' % (api_response)
            try:
                response = yaml.load(data)
            except:
                data = data.replace(': Core', ' Core')
                response = yaml.load(data)
        if response:
            if 'vulnerabilities' in response:
                response['vulnerabilities_total'] = response['vulnerabilities'].copy()
                vulnerabilities = []
                vulnerability_ids = self.get_vulnerability_ids_by_asset_id(asset_id)
                for vulnerability in vulnerability_ids:
                    if 'id' not in vulnerability:
                        continue
                    v = self.get_vulnerability_by_id(vulnerability['id'])
                    vulnerabilities.append(v)
                response['vulnerabilities'] = vulnerabilities
            return response
        return None

    def get_vulnerability_by_id(self, vulnerability_id=None):
        response = {}
        if not vulnerability_id:
            return response
        vuln_ref_file = None
        if self.vuln_ref_dir:
            vuln_ref_file = os.path.join(self.vuln_ref_dir, vulnerability_id + '.yaml')
            if os.path.exists(vuln_ref_file):
                # read data from file
                with open(vuln_ref_file) as f:
                    response = yaml.load(f);
                return response
        api_instance = py_insightvm_sdk.VulnerabilityApi(self.api_client)
        try:
            api_response = api_instance.get_vulnerability(vulnerability_id)
            response = yaml.load('%s' % (api_response))
        except:
            pass
        if vuln_ref_file:
            # write data to file
            with open(vuln_ref_file, 'w') as f:
                yaml.safe_dump(response, f, default_flow_style=False, encoding='utf-8', allow_unicode=True);
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
        return response

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

    def _serialize_json(self, data):
        if isinstance(data, (dict)):
            new_data = {}
            for k in data:
                new_data[k] = self._serialize_json(data[k])
            return new_data
        if isinstance(data, (list)):
            new_data = []
            for entry in data:
                new_data.append(self._serialize_json(entry))
            return new_data
        elif isinstance(data, (datetime)):
            return data.isoformat()
        else:
            pass
        return data

