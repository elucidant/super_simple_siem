from __future__ import absolute_import, print_function, unicode_literals

import json, logging, sys, gzip, csv
from logging import getLogger
from alert_collection import AlertCollection

logger = getLogger('super_simple_siem_alert')

def parse_mv_field(s):
    # s appears to be utf-8 encoded
    # need to work on unicode char set and assume we need to give back utf-8
    res = []
    if (not s) or (s[0] != '$' and s[-1] != '$') :
        return res
    else:
        f = ''
        i = 1 # first and last char will be $
        ss = s.decode('utf-8')
        while i < len(ss) - 1:
            if ss[i:(i+2)] == '$$':
                f += '$'
                i += 2
            elif ss[i:(i+3)] == '$;$':
                res.append(f.encode('utf-8'))
                f = ''
                i += 3
            else:
                f += ss[i]
                i += 1
        res.append(f.encode('utf-8'))
        return res

payload = json.loads(sys.stdin.read())

session_key = payload['session_key']

max_count = int(payload['configuration']['max_count'])

alerts = AlertCollection(session_key)

results_file = payload['results_file']

with gzip.open(results_file, 'rt') as f:
    file_content = csv.reader(f)
    lines = list(file_content)
    header = lines[0]
    rows = lines[1:]

    # cap how many alerts can be created if it is defined
    if max_count > 0:
        rows = rows[0:max_count]

    for row in rows:
        record_all = dict(zip(header, row))
        record = {k:v for k,v in record_all.items() if not k.startswith('__mv_')}
        # if fields has a multi-value version,  replace with array
        for k in record.keys():
            mvname = '__mv_' + k
            if (mvname in record_all) and (record_all[mvname]):
                try:
                    mvvalue = parse_mv_field(record_all[mvname])
                    if mvvalue:
                        record[k] = mvvalue
                except:
                    logger.error('Could not parse multivalue ' + str(record_all[mvname]))

        alerts.insert_custom_alert(
            record = record,
            event_time=payload['configuration']['time'],
            entity=payload['configuration']['entity'],
            alert_type=payload['configuration']['type'],
            severity=payload['configuration']['severity'],
            app=payload['app'],
            owner=payload['owner'],
            search_name=payload['search_name'],
            sid=payload['sid'],
            server_host=payload['server_host'],
            server_uri=payload['server_uri'],
            search_uri=payload['search_uri'],
            results_link=payload['results_link'],
            logger=logger
        )

