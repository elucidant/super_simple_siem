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
import sys
from header_backport import header


@Configuration()
class DecodeHeaderCommand(StreamingCommand):
    """ Decode an smtp header using python's email.header.decode_header function.

    ##Syntax

    .. code-block::
        decodeheader inputfield=<field> outputfield=<field>

    ##Description

    If inputfield exists, it's value is decoded as an encoded email header and stored in outputfield.
    Event records are otherwise passed through to the next pipeline processor unmodified.

    ##Example

    Decode `subject` and stored in `decoded_subject`.

    .. code-block::
        | decodeheader inputfield=subject outputfield=decoded_subject

    """
    inputfield = Option(
        doc='''
        **Syntax:** **inputfield=***<fieldname>*
        **Description:** Name of the field that holds the header value''',
        require=True, validate=validators.Fieldname())

    outputfield = Option(
        doc='''
        **Syntax:** **outputfield=***<fieldname>*
        **Description:** Name of the field that will hold the decoded header value''',
        require=True, validate=validators.Fieldname())

    def stream(self, records):
        self.logger.debug('DecodeHeaderCommand: %s', self)  # logs command line
        default_charset = 'ASCII'
        for record in records:
            if self.inputfield in record:
                try:
                    dh = header.decode_header(record[self.inputfield])
                    s = ''.join([unicode(t[0], t[1] or default_charset) for t in dh ])
                    record[self.outputfield] = s
                except Exception as e:
                    record[self.outputfield + '_err'] = str(e)
                yield record

dispatch(DecodeHeaderCommand, sys.argv, sys.stdin, sys.stdout, __name__)
