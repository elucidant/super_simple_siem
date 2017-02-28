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
class DeleteAlertsCommand(StreamingCommand):

    key = Option(
        doc='''
        **Syntax:** **key=***<field>*
        **Description:** The internal key of the alert''',
        require=True, validate=validators.Fieldname())

    alerts = None

    def stream(self, records):
        self.logger.info('DeleteAlertsCommand: %s', self)  # logs command line
        if not self.alerts:
            self.alerts = AlertCollection(self._metadata.searchinfo.session_key)

        for record in records:
            if self.key in record:
                self.alerts.delete(record[self.key], logger=self.logger)
            else:
                self.logger.error('DeleteAlertsCommand: no key field %s', str(self.json))  # logs command line
            yield record

dispatch(DeleteAlertsCommand, sys.argv, sys.stdin, sys.stdout, __name__)

