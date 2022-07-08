#!/usr/bin/env python
# coding=utf-8
#
# Copyright 2016-2017 Jean-Laurent Huynh
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, unicode_literals

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import time
import sys, json
from splunklib.client import connect
from alert_collection import AlertCollection


# Note that distibuted parameter below is flipped True means: it will only run on the search head.
@Configuration(type='streaming', distributed=False, streaming=True)
class ListAlertsCommand(GeneratingCommand):

    data = Option(
        doc='''
        **Syntax:** **data=***<field>*
        **Description:** Field name that will receive the alert data in json format''',
        require=False, validate=validators.Fieldname())
    data_prefix = Option(
        doc='''
        **Syntax:** **data_prefix=***<string>*
        **Description:** Prefix that will be inserted before the data fields. Each data field will appear as a separate field.''',
        require=False)
    json_field = Option(
        doc='''
        **syntax:** **raw=***<field>*
        **description:** field name that will receive the entire record as a json object.''',
        require=False, name='json', validate=validators.Fieldname())
    status = Option(
        doc='''
        **syntax:** **status=***<comma_separated_list_of_status>*
        **description:** Only selects alerts with the provided statuses''',
        require=False)
    type = Option(
        doc='''
        **syntax:** **type=***<comma_separated_list_of_types>*
        **description:** Only selects alerts with the provided types''',
        require=False)
    severity = Option(
        doc='''
        **syntax:** **severity=***<comma_separated_list_of_severity>*
        **description:** Only selects alerts with the provided severity''',
        require=False)
    analyst = Option(
        doc='''
        **syntax:** **analyst=***<comma_separated_list_of_analyst>*
        **description:** Only selects alerts with the provided analysts''',
        require=False)
    #count = Option(require=True, validate=validators.Integer(0))
    alerts = None

    def generate(self):
        self.logger.info('ListAlertsCommand: %s', self)
        if not self.alerts:
            self.alerts = AlertCollection(self._metadata.searchinfo.session_key)
        if self.status:
            status = self.status.split(',')
        else:
            status = []
        if self.type:
            type = self.type.split(',')
        else:
            type = []
        if self.severity:
            severity = self.severity.split(',')
        else:
            severity = []
        if self.analyst:
            analyst = self.analyst.split(',')
        else:
            analyst = []
        if self._metadata.searchinfo.earliest_time != 0:
            earliest_time = self._metadata.searchinfo.earliest_time
        else:
            earliest_time = None
        if self._metadata.searchinfo.latest_time != 0:
            latest_time = self._metadata.searchinfo.latest_time
        else:
            latest_time = None
        for record in self.alerts.list(status=status, type=type,
                severity=severity,
                analyst=analyst,
                earliest_time=earliest_time, latest_time=latest_time,
                logger=self.logger):
            event = {
                '_time': record['time'],
                'sourcetype': 'alerts',
                'type': record['type'],
                'severity': record.get('severity'),
                'entity': record['entity'],
                'kv_key': record['_key'],
                'analyst': record.get('analyst'),
                'status': record['status'],
                'sid': record['sid']
            }
            data = record['data']

            if self.data:
                event[self.data] = json.dumps(record['data'])
            if self.data_prefix is not None:
                for key, value in data.items():
                    event[self.data_prefix + key] = value
            if self.json_field:
                event[self.json_field] = json.dumps(record)

            yield event

dispatch(ListAlertsCommand, sys.argv, sys.stdin, sys.stdout, __name__)

