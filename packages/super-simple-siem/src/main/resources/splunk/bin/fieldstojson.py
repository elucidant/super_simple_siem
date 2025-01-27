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
import sys, json, collections
from splunklib.client import connect

@Configuration()
class FieldsToJsonCommand(StreamingCommand):
    json = Option(
        doc='''
        **Syntax:** **json=***<field>*
        **Description:** Field name that receives the json string''',
        require=True, validate=validators.Fieldname())
    prefix = Option(
        doc='''
        **Syntax:** **prefix=***<string>*
        **Description:** Any field that is prefixed with this string is serialized.''',
        require=True)

    def stream(self, records):
        self.logger.info('FieldsToJsonCommand: %s', self)  # logs command line
        for record in records:
            json_obj = {}
            for key, value in record.iteritems():
                if key[2:].startswith(self.prefix):
                    tp = key[0]
                    actual_key = key[(2+len(self.prefix)):]
                    if tp == 's':
                        json_obj[actual_key] = value
                    elif tp == 'l':
                        json_obj[actual_key] = long(value)
                    elif tp == 'i':
                        json_obj[actual_key] = int(value)
                    elif tp == 'f':
                        json_obj[actual_key] = float(value)
                    elif tp == 'j':
                        json_obj[actual_key] = json.loads(value)
                    elif tp == 'a':
                        json_obj[actual_key] = [ json.loads(v) for v in value ]
            record[self.json] = json.dumps(json_obj)
            yield record

dispatch(FieldsToJsonCommand, sys.argv, sys.stdin, sys.stdout, __name__)

