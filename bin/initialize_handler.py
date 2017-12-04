# Copyright 2016-2017 Jean-Laurent Huynh
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#           http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import splunk.admin as admin
import splunk.entity as en

from splunklib.client import connect
from splunklib.binding import HTTPError
import os
import os.path
from alert_collection import AlertCollection

class ConfigApp(admin.MConfigHandler):

    app_name = AlertCollection.app_name

    '''
    Set up supported arguments
    '''
    def setup(self):
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in ['initialization']:
                self.supportedArgs.addOptArg(arg)

    def handleList(self, confInfo):
        confInfo['setupentity'].append('initialization', '1')

    def handleEdit(self, confInfo):
        name = self.callerArgs.id
        args = self.callerArgs

        if int(self.callerArgs.data['initialization'][0]) == 1:
            # run initialization
            service = connect(token=self.getSessionKey())
            pass
            self.initialize_lookups(service)

    def get_app_path(self, service):
        return os.path.join(service.settings.SPLUNK_HOME, "etc", "apps", self.app_name)

    def initialize_lookup(self, service, lookup_name):
        s3_path = self.get_app_path(service)
        csvfile = lookup_name + ".csv"
        templ_path = os.path.join(s3_path, "template", csvfile)
        lookups_dir = os.path.join(s3_path, "lookups")
        lookups_csvfile = os.path.join(lookups_dir, csvfile)
        if not os.path.exists(lookups_dir):
            os.makedirs(lookups_dir)
        if not os.path.exists(lookups_csvfile):
            if os.path.exists(templ_path):
                import shutil
                shutil.copy(templ_path, lookups_csvfile)
            else:
                raise OSError("File not found: %s" % templ_path)

        path = "/servicesNS/nobody/" + self.app_name + "/properties/transforms/" + lookup_name
        path_fn = path + "/filename"
        try:
            current = service.get(path_fn)
        except HTTPError as e:
            if (e.status == 404):
                # Cannot find property, will create it
                conf_path = "/servicesNS/nobody/" + self.app_name + "/configs/conf-transforms"
                service.post(conf_path, name=lookup_name, filename=csvfile)
            else:
                raise e

    def initialize_lookups(self, service):
        for table in ["analysts", "canned_queries", "severities", "threats_to_actions", "whitelist"]:
            self.initialize_lookup(service, table)

# initialize the handler
admin.init(ConfigApp, admin.CONTEXT_NONE)

