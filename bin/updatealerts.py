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
from alert_collection import AlertCollection

@Configuration()
class UpdateAlertsCommand(StreamingCommand):

    json = Option(
        doc='''
        **Syntax:** **json=***<field>*
        **Description:** Field name that contains the alert as a json string''',
        require=False, validate=validators.Fieldname())

    key = Option(
        doc='''
        **Syntax:** **key=***<field>*
        **Description:** The internal key of the alert''',
        require=False, validate=validators.Fieldname())

    status = Option(
        doc='''
        **Syntax:** **status=***<string>*
        **Description:** The new status''',
        require=False)

    action = Option(
        doc='''
        **Syntax:** **action=***<string>*
        **Description:** The action''',
        require=False)

    notes = Option(
        doc='''
        **Syntax:** **notes=***<string>*
        **Description:** Optional notes to be added to the work log''',
        require=False)

    notes_field = Option(
        doc='''
        **Syntax:** **notes_field=***<field>*
        **Description:** Value of the field will be used as notes to be added to the work log, takes precedence over the notes option''',
        require=False, validate=validators.Fieldname())

    alerts = None

    def stream(self, records):
        self.logger.info('UpdateAlertsCommand: %s', self)  # logs command line
        #self.logger.info('SEARCHINFO %s', self._metadata.searchinfo)
        if not self.alerts:
            self.alerts = AlertCollection(self._metadata.searchinfo.session_key)

        for record in records:
            if self.json and self.json in record:
                self.alerts.replace(json.loads(record[self.json]),
                    notes = self.notes,
                    logger=self.logger,
                    sid=self._metadata.searchinfo.sid,
                    username=self._metadata.searchinfo.username)
            elif self.action and self.status and self.key and self.key in record:
                notes = None
                if self.notes:
                    notes = self.notes
                if self.notes_field and self.notes_field in record and record[self.notes_field]:
                    notes = record[self.notes_field]
                self.alerts.update(record[self.key], action=self.action, status=self.status, notes=notes,
                    logger=self.logger,
                    sid=self._metadata.searchinfo.sid,
                    username=self._metadata.searchinfo.username)
            else:
                self.logger.error('json field should be present OR the key field, action value and status value should be provided')

            yield record

dispatch(UpdateAlertsCommand, sys.argv, sys.stdin, sys.stdout, __name__)

