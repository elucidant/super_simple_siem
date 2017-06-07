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

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import sys, json
from splunklib.client import connect
from alert_collection import AlertCollection, InsertStats

@Configuration()
class MakeAlertsCommand(StreamingCommand):
    time = Option(
        doc='''
        **Syntax:** **time=***<field>*
        **Description:** Field name used to determine event time for the alert''',
        require=False, validate=validators.Fieldname(), default='_time')
    entity = Option(
        doc='''
        **Syntax:** **entity=***<field>*
        **Description:** Field name used to determine the entity triggering the alert (account name, machine name, ...)''',
        require=False, validate=validators.Fieldname(), default='entity')
    alert_type = Option(
        doc='''
        **Syntax:** **type=***<string>*
        **Description:** Field name used to determine the type of alert''',
        require=True, name='type')
    severity = Option(
        doc='''
        **Syntax:** **severity=***<field>*
        **Description:** Field name used to set severity of the alert''',
        require=False, validate=validators.Fieldname(), default=None)
    idfield = Option(
        doc='''
        **Syntax:** **idfield=***<field>*
        **Description:** Field name used to store the alert id''',
        require=False, default=None, validate=validators.Fieldname())
    combine = Option(
        doc='''
        **Syntax:** **combine=***"<fields>"*
        **Description:** Comma separated field names where alerts should be combined instead of creating new ones.''',
        require=False, default=None)
    combine_window = Option(
        doc='''
        **Syntax:** **combine_window=***<string>*
        **Description:** hours or days. ''',
        require=False, default=None)

    alerts = None

    def __init__(self):
        super(MakeAlertsCommand, self).__init__()
        self.insert_stats = InsertStats()


    def stream(self, records):
        #self.logger.info('MakeAlertsCommand: %s, type of record %s', self, type(records))  # logs command line
        #self.logger.info('SEARCHINFO %s', self._metadata.searchinfo)
        is_scheduled = self._metadata.searchinfo.sid.startswith("scheduler_")
        if not self.alerts:
            self.alerts = AlertCollection(self._metadata.searchinfo.session_key)

        for record in records:
            self.alerts.insert(record,
                event_time=self.time,
                entity=self.entity,
                alert_type=self.alert_type,
                severity=self.severity,
                idfield=self.idfield,
                combine=self.combine,
                combine_window=self.combine_window,
                search_query=self._metadata.searchinfo.search,
                search_earliest=self._metadata.searchinfo.earliest_time,
                search_latest=self._metadata.searchinfo.latest_time,
                logger=self.logger,
                sid=self._metadata.searchinfo.sid,
                username=self._metadata.searchinfo.username,
                insert_stats=self.insert_stats)
            yield record

    def finish(self):
        self.logger.info('calling finish: %s', str(self.insert_stats))
        try:
            super(MakeAlertsCommand, self).finish()
        except:
            pass

dispatch(MakeAlertsCommand, sys.argv, sys.stdin, sys.stdout, __name__)


