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
from splunklib import results
from alert_collection import AlertCollection, SearchContext, InsertStats
from criteria_parser import CriteriaParser, Context
import datetime
import logging

class CustomLogAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        #return 'sid=%s,type="%s",%s' % (self.extra['sid'], self.extra['type'], msg), kwargs
        return 'sid=%s,type=%s,%s' % (self.extra['sid'], self.extra['type'], msg), kwargs

class Whitelist:
    # assume we have the following fields:
    # start and end (in YYYY-MM-DD format): only apply alert if current date is between start and end
    def __init__(self, row):
        self.row = row
        self.name = row['name']
        self.type = row['type']
        self.start = datetime.datetime.strptime(row['start'], "%Y-%m-%d")
        self.end = datetime.datetime.strptime(row['end'], "%Y-%m-%d")
        self.criteria = None

    def parse_criteria(self):
        cp = CriteriaParser()
        self.criteria = cp.parse(self.row['criteria'])

    def __str__(self):
        return (
        "Whitelist(name=" + self.name + ", type=" + self.type + ", start=" + str(self.start) + ", end=" + str(self.end)
            + ", criteria=" + str(self.criteria) + ") parsed from " + str(self.row)
        )

    # Returns true if the alert described by the record is whitelisted
    def is_whitelisted(self, context):
        return self.criteria.evaluate(context)

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
    interactive = Option(
        doc='''
        **Syntax:** **interactive=***<bool>*
        **Description:** If true, makealerts can run in an interactive search, otherwise it will run only in scheduled
        search (this is to prevent alerts created accidentally when copy and pasting scheduled search text)''',
        require=False, default=False, validate=validators.Boolean())
    preview = Option(
        doc='''
        **Syntax:** **preview=***<bool>*
        **Description:** If true, makealerts does not create alerts but instead indicates what it would do in the
        preview field''',
        require=False, default=False, validate=validators.Boolean())

    alerts = None

    def __init__(self):
        super(MakeAlertsCommand, self).__init__()
        self.insert_stats = InsertStats()
        self.whitelist = []
        self.whitelist_loaded = False
        self.loggerExtra = self.logger

    def load_whitelist(self, searchinfo):
        if not self.whitelist_loaded:
            self.whitelist_loaded = True
            service = connect(token=searchinfo.session_key, app=searchinfo.app)
            rr = results.ResultsReader(service.jobs.oneshot("| inputlookup whitelist"))
            today = datetime.datetime.today()
            for result in rr:
                if isinstance(result, results.Message):
                    self.logger.error(
                    "sid=%s,s3tag=whitelist,type=%s,message=%s", searchinfo.sid, result.type, result.message)
                elif self.alert_type == result['type']:
                    try:
                        wl = Whitelist(result)
                        if today >= wl.start and today <= wl.end:
                            wl.parse_criteria()
                            self.whitelist.append(wl)
                    except Exception as e:
                        self.logger.error("sid=%s,s3tag=whitelist,type=\"invalid whitelist\",message=\"%s\",record=%s",
                            searchinfo.sid, str(e), str(result))

    def is_scheduled(self):
        sid = self._metadata.searchinfo.sid
        return sid.startswith("scheduler_") or sid.startswith("rt_scheduler_")

    def stream(self, records):
        #self.logger.info('MakeAlertsCommand: %s, type of record %s', self, type(records))  # logs command line
        #self.logger.info('SEARCHINFO %s', self._metadata.searchinfo)

        sid = self._metadata.searchinfo.sid
        self.loggerExtra = CustomLogAdapter(self.logger, {'sid': sid, 'type': self.alert_type})

        if not self.interactive and not self.is_scheduled():
            raise RuntimeError("When testing makealerts from interactive search, provide the 'interative=t' option.")

        if not self.alerts:
            self.alerts = AlertCollection(self._metadata.searchinfo.session_key)

        for record in records:
            self.load_whitelist(self._metadata.searchinfo)
            for wl in self.whitelist:
                context = Context(record)
                if wl.is_whitelisted(context):
                    self.insert_stats.whitelisted += 1
                    self.loggerExtra.info("s3tag=criteria,evaluation=\"%s\"", str(context.debug))
                    self.loggerExtra.info("s3tag=whitelisted,name=\"%s\"", wl.name)
                    if self.preview:
                        record['preview'] = 'whitelisted %s' % str(context.debug)
                    break
            else:
                search_context = SearchContext(self._metadata.searchinfo, self.loggerExtra)
                self.alerts.insert(record,
                    event_time=self.time,
                    entity=self.entity,
                    alert_type=self.alert_type,
                    severity=self.severity,
                    idfield=self.idfield,
                    combine=self.combine,
                    combine_window=self.combine_window,
                    preview=self.preview,
                    search_context=search_context,
                    insert_stats=self.insert_stats)
                if self.preview:
                    record['preview'] = str(search_context.messages)
            yield record

    def finish(self):
        if self.interactive and (not self.is_scheduled()) and self.insert_stats.errors > 0:
           self.write_error(
               "There were {0} error(s) when trying to insert data, check logs with this search 'index=_internal MakeAlertsCommand source=*super_simple_siem.log* ERROR'",
               self.insert_stats.errors)

        if not self.preview:
            self.loggerExtra.info('s3tag=stats,%s,whitelist=%s',
                str(self.insert_stats),
                "[" + ";".join(str(x) for x in self.whitelist) + "]")

        try:
            super(MakeAlertsCommand, self).finish()
        except:
            pass

dispatch(MakeAlertsCommand, sys.argv, sys.stdin, sys.stdout, __name__)


