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
class JsonToFieldsCommand(StreamingCommand):
    json = Option(
        doc='''
        **Syntax:** **json=***<field>*
        **Description:** Field name that contains the json string''',
        require=True, validate=validators.Fieldname())
    prefix = Option(
        doc='''
        **Syntax:** **prefix=***<string>*
        **Description:** Prefix to use to expand fields''',
        require=False)
    typeprefix = Option(
        doc='''
        **Syntax:** **typeprefix=***<bool>*
        **Description:** If true, prefix fields with a letter indicating the type (long, int, float, string, json, array)''',
        require=False, default=False, validate=validators.Boolean())

    def stream(self, records):
        self.logger.info('JsonToFieldsCommand: %s', self)  # logs command line
        for record in records:
            json_str = record.get(self.json)
            if json_str:
                json_obj = json.loads(json_str)
                if self.prefix:
                    prefix = self.prefix 
                else:
                    prefix = ""
                for key, value in json_obj.items():
                    if (not self.fieldnames) or (key in self.fieldnames):
                        if isinstance(value, str):
                            if self.typeprefix:
                                tp = "s_"
                            else:
                                tp = ""
                            record[tp + prefix + key] = value
                        elif isinstance(value, collections.Mapping):
                            if self.typeprefix:
                                tp = "j_"
                            else:
                                tp = ""
                            record[tp + prefix + key] = json.dumps(value)
                        elif isinstance(value, collections.Sequence):
                            if self.typeprefix:
                                tp = "a_"
                            else:
                                tp = ""
                            record[tp + prefix + key] = [ json.dumps(s) for s in value ]
                        else:
                            if self.typeprefix:
                                if isinstance(value, int):
                                    tp = "i_"
                                elif isinstance(value, float):
                                    tp = "f_"
                                elif isinstance(value, long):
                                    tp = "l_"
                                else:
                                    tp = "x_"
                            else:
                                tp = ""
                            record[tp + prefix + key] = value
            else:
                self.logger.warn('JsonToFieldsCommand: no field named %s', self.json)
            yield record

dispatch(JsonToFieldsCommand, sys.argv, sys.stdin, sys.stdout, __name__)

