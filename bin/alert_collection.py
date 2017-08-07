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

import sys, json
from splunklib.client import connect
from utils import parse
import time
import logging

# This is used to pass information to log things in context as well as report messages.
class SearchContext:

    def __init__(self, searchinfo, logger):
        self.searchinfo = searchinfo or {
            'sid': None,
            'search': None,
            'earliest_time': None,
            'latest_time': None
        }
        self.logger = logger or logging.getLogger('SearchContext').addHandler(logging.NullHandler())
        self.messages = []


class AlertCollection:
    app_name = 'super_simple_siem'
    coll_name  = 'alerts'

    def __init__(self, session_key):
        self.session_key = session_key
        self.alert_service = connect(token=session_key, app=self.app_name)
        self.coll = self.alert_service.kvstore[self.coll_name]

    def purge(self):
        self.coll.data.delete()

    def fix_field_name(self, field_name):
        import re
        return re.sub('[.$]', '', field_name)


    # insert the record or combine with an existing record (if combine and combine_window allow it).
    #   combining is based on type, entity, time and data subject to combine and combine_window constraints.
    #   when combining, the main alert data is preserved, additional information is added to the work log.
    # do no insert duplicate records (same type, entity, time and data).
    # if logger is provided, log duplicate records for troubleshooting.
    # if insert_stats is provided, tabulate counts of insert status
    def insert(self, record,
            event_time='_time',
            entity='entity',
            alert_type='type',
            severity=None,
            idfield=None,
            combine=None,
            combine_window=None,
            preview=False,
            search_context=None,
            insert_stats=None):
        import re
        logger = search_context.logger
        if insert_stats is None:
            insert_stats = InsertStats()
        if event_time in record and entity in record:
            sid = search_context.searchinfo.sid

            alert_data = {self.fix_field_name(key): value for key, value in record.iteritems() if key[0] != '_'}
            alert_record = { 'data': alert_data }
            alert_record['time'] = float(record[event_time])
            alert_record['entity'] = record[entity]
            alert_record['type'] = alert_type
            alert_record['status'] = 'open'
            if severity:
                alert_record['severity'] = record[severity]
            alert_record['analyst'] = None
            alert_record['sid'] = sid
            alert_record['search_query'] = search_context.searchinfo.search
            alert_record['search_earliest'] = search_context.searchinfo.earliest_time
            alert_record['search_latest'] =search_context.searchinfo.latest_time
            alert_record['work_log'] = [ {
                'time': time.time(),
                'action': 'create',
                'notes': None,
                'data': {},
                'analyst': search_context.searchinfo.username
            } ]
            if combine and combine_window:
                hours = re.match(r'(\d+)(hours?|h)', combine_window)
                days = re.match(r'(\d+)(days?|d)', combine_window)
                if hours:
                    delta_seconds = int(hours.group(1)) * 3600
                elif days:
                    delta_seconds = int(days.group(1)) * 3600 * 24
                else:
                    logger.error("message=\"Cannot parse combine_window %s, default to 24h\"", combine_window)
                    delta_seconds = 3600 * 24
                cutoff = alert_record['time'] - delta_seconds
                fields = combine.split(",")
                def same_fields(old, new):
                   return reduce(lambda a, b: a and b, map(lambda f: old['data'][f] == new['data'][f], fields))
                candidates0 = [ a for a in self.find(alert_record['type'], alert_record['entity'], cutoff) ]
                candidates1 = [ a for a in candidates0 if (a['status'] == 'open' or a['status'] == 'assigned') ]
                candidates2 = [ a for a in candidates1 if same_fields(a, alert_record) ]
                if candidates2:
                    existing = candidates2[0]
                    if existing['data'] == alert_record['data']:
                        record[idfield] = existing['_key']
                        insert_stats.duplicate += 1
                        search_context.messages.append('alert not created, duplicate of %s' % existing['_key'])
                        logger.info('DUPLICATE alert_record: %s', alert_record)
                    else:
                        alert_data['sid'] = sid
                        existing['work_log'].insert(0, {
                                'time': time.time(),
                                'action': 'combine',
                                'notes': None,
                                'data': alert_data,
                                'analyst': search_context.searchinfo.username
                            })
                        if not preview:
                            self.coll.data.update(existing['_key'], json.dumps(existing))
                        search_context.messages.append('alert %s would be updated' % existing['_key'])
                        insert_stats.merged += 1
                else:
                    if not preview:
                        alert_id = self.coll.data.insert(json.dumps(alert_record))
                        if idfield:
                            record[idfield] = alert_id['_key']
                    insert_stats.inserted += 1
                    search_context.messages.append('alert would be inserted')
            else:
                same_existing_alerts = [ a for a
                    in self.find(alert_record['type'], alert_record['entity'], alert_record['time'])
                    if a['data'] == alert_record['data']
                ]
                if not same_existing_alerts:
                    if not preview:
                        alert_id = self.coll.data.insert(json.dumps(alert_record))
                        if idfield:
                            record[idfield] = alert_id['_key']
                    search_context.messages.append('alert would be inserted')
                    insert_stats.inserted += 1
                else:
                    if idfield:
                        record[idfield] = same_existing_alerts[0]['_key']
                    search_context.messages.append(
                        'alert not created, duplicate of %s' % same_existing_alerts[0]['_key'])
                    insert_stats.duplicate += 1
                    logger.info('DUPLICATE alert_record: %s', alert_record)
        else:
            missing = set([event_time, entity, alert_type]) - set(record.keys())
            search_context.messages.append('alert not inserted, missing fields %s' % str(missing))
            logger.error('message="Missing fields in record: %s"', missing)
            insert_stats.errors += 1

    # CSV file with a single json column with the json as exported by | listalerts json=json
    def csv_import(self, file_of_json_inside_csv):
        import csv
        with open(file_of_json_inside_csv, 'rb') as csvfile:
            rows = csv.reader(csvfile)
            for row in rows:
                if row[0] != 'json':
                    self.coll.data.insert(row[0])

    def replace(self, alert_record, notes=None, logger=None, sid=None, username=None):
        key = alert_record.get("_key")
        if key:
            if notes:
                alert_record['work_log'].insert(0, {
                        'time': time.time(),
                        'action': 'update',
                        'notes': notes,
                        'data': {'sid': sid},
                        'analyst': username
                    })
            self.coll.data.update(key, json.dumps(alert_record))
        else:
            logger.error('message="Cannot find alert: %s"', str(key))

    def update(self, key, action, status, notes=None, logger=None, sid=None, username=None):
        if key:
            alert_record = self.coll.data.query_by_id(key)
            alert_record['status'] = status
            alert_record['work_log'].insert(0, {
                    'time': time.time(),
                    'action': action,
                    'notes': notes,
                    'data': {'sid': sid},
                    'analyst': username
                })
            self.coll.data.update(key, json.dumps(alert_record))
        else:
            logger.error('sid=%s,message="Cannot find alert: %s"', sid, str(key))

    def delete(self, key, logger=None):
        if key:
            self.coll.data.delete_by_id(key)
        else:
            logger.error('sid=%s,message="Cannot find alert: %s"', sid, str(key))

    def find(self, type, entity, time_gte):
        """Find records for the type, entity and time (int)."""
        q = {
            'type': type,
            'entity': entity,
            'time': { '$gte': time_gte}
        }
        encoded = json.dumps(q)
        return self.coll.data.query(query=encoded)

    def list(self, status = [], type=[], severity=[], analyst=[], entity=[],
            earliest_time=None, latest_time=None,
            logger=None):
        if status or type or analyst or entity or severity:
            if status:
                qs = { '$or': [{ 'status': s } for s in status] }
            else:
                qs = {}
            if type:
                qt = { '$or': [{ 'type': s } for s in type] }
            else:
                qt = {}
            if analyst:
                qa = { '$or': [{ 'analyst': s } for s in analyst] }
            else:
                qa = {}
            if entity:
                qe = { '$or': [{ 'entity': s } for s in entity] }
            else:
                qe = {}
            if severity:
                qss = { '$or': [{ 'severity': s } for s in severity] }
            else:
                qss = {}
            clauses = []
            if qs: clauses.append(qs)
            if qt: clauses.append(qt)
            if qa: clauses.append(qa)
            if qe: clauses.append(qe)
            if qss: clauses.append(qss)
            if earliest_time: clauses.append({'time': {'$gte': earliest_time}})
            if latest_time: clauses.append({'time': {'$lt': latest_time}})
            encoded = json.dumps({ '$and': clauses })
            res =  self.coll.data.query(query=encoded)
        else:
            if earliest_time or latest_time:
                clauses = []
                if earliest_time: clauses.append({'time': {'$gte': earliest_time}})
                if latest_time: clauses.append({'time': {'$lt': latest_time}})
                encoded = json.dumps({ '$and': clauses })
                res =  self.coll.data.query(query=encoded)
            else:
                res = self.coll.data.query()
        return sorted(res, key=lambda r: -r['time'])

    def dump(self):
        print("Collection data: %s" % json.dumps(self.coll.data.query(), indent=1))

def main():
    opts = parse(sys.argv[1:], {}, ".splunkrc")
    #print(opts)
    service = connect(**opts.kwargs)
    alerts = AlertCollection(service.token)
    if 'purge' in sys.argv:
        alerts.purge()
    elif 'dump' in sys.argv:
        alerts.dump()
    elif 'import'in sys.argv and len(sys.argv) == 3:
        filename = sys.argv[2]
        alerts.csv_import(filename)

if __name__ == "__main__":
    main()

class InsertStats:
    def __init__(self):
        self.inserted = 0
        self.duplicate = 0
        self.merged = 0
        self.errors = 0
        self.whitelisted = 0
    def __str__(self):
        return 'inserted=%d,duplicate=%d,merged=%d,errors=%d,whitelisted=%d' % (
        self.inserted, self.duplicate, self.merged, self.errors, self.whitelisted)
