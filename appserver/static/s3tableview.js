/*
Copyright 2017 Jean-Laurent Huynh

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

require.config({
    paths: {
        datatables: "/static/app/super_simple_siem/datatables"
    },

    shim: {
    }
});

define([
        "backbone",
        "splunkjs/mvc",
        "splunkjs/mvc/utils",
        "splunkjs/mvc/searchmanager",
        'splunkjs/mvc/simplesplunkview',
        "splunkjs/mvc/multidropdownview",
        'datatables/datatables',
        'underscore',
        'jquery',
        'moment'
    ], function(
        Backbone,
        mvc,
        utils,
        SearchManager,
        SimpleSplunkView,
        MultiDropdownView,
        DataTables,
        _,
        $,
        moment
        ) {
    // Base class for custom views
    var SimpleSplunkView = require('splunkjs/mvc/simplesplunkview');

    // Define the custom view class
    var S3TableView = SimpleSplunkView.extend({
        className: "s3tableview",

        options: {
            data: "results",
            analysts: [],
            severities: [],
            threatsToActions: {}
        },

        initialize: function(options) {
            SimpleSplunkView.prototype.initialize.apply(this, [options])
            this.outputMode = 'json';
            this.threatActionSelectMap = {}
            this.service = mvc.createService({ owner: "nobody" });
            this.filter = new Backbone.Model({
                type: [],
                analyst: [],
                severity: [],
                status: [],
                earliest_time: null,
                latest_time: "now"
            });
            this.listenTo(this.filter, "change", this.onFilterChange);

            this.analystDropDownSearchResults = new SearchManager({
                id: "analysts-search",
                preview: false,
                cache: false,
                search: "| inputlookup analysts" 
            }).data('results');
            this.analystDropDownSearchResults.on("data", function() {
                var analysts = _.map(this.analystDropDownSearchResults.data().rows, function(row) {
                    return row[0];
                });
                this.settings.set("analysts", analysts);
            }, this);

            this.threatsToActionsResults = new SearchManager({
                id: "threats-to-actions-search",
                preview: false,
                cache: false,
                search: "| inputlookup threats_to_actions | table Threat, Actions" 
            }).data('results');
            this.threatsToActionsResults.on("data", function() {
                var threatsToActions = _.object(
                    _.map(this.threatsToActionsResults.data().rows, function(row) {
                        return [row[0], row[1].split(",")];
                    })
                );
                this.settings.set("threatsToActions", threatsToActions);
            }, this);

            this.severityDropDownSearchResults = new SearchManager({
                id: "severity-search",
                preview: false,
                cache: false,
                search: "| inputlookup severities"
            }).data('results');
            this.severityDropDownSearchResults.on("data", function() {
                var severities = _.map(this.severityDropDownSearchResults.data().rows, function(row) {
                    return row[0];
                });
                this.settings.set("severities", severities);
            }, this);

            this.cannedQueriesSearchResults = new SearchManager({
                id: "canned-queries-search",
                preview: false,
                cache: false,
                search: "| inputlookup canned_queries"
            }).data('results');
            this.cannedQueriesSearchResults.on("data", function() {
                var data = this.cannedQueriesSearchResults.data();
                var canned_queries = _.indexBy(_.map(data.rows, function(row) {
                    var item = {};
                    for (i = 0; i < data.fields.length; i++) {
                        item[data.fields[i]] = row[i];
                    }
                    return item;
                }), 'type');
                this.settings.set("canned_queries", canned_queries);
            }, this);


            // create manager before we set managerid so that the component can properly
            // configure the manager (uses Splunk view binding machinery)
            this.managerId = this.id + "-search";
            var manager = new SearchManager({
                "id": this.managerId, 
                "earliest_time": null,
                "cancelOnUnload": true,
                "status_buckets": 0,
                "latest_time": "now",
                "sample_ratio": null,
                "app": utils.getCurrentApp(),
                "auto_cancel": 90,
                "preview": true,
                "runWhenTimeIsUndefined": false
            }, {});
            this.bindToComponentSetting('managerid', this.onFilterChange, this);
            this.settings.set("managerid", this.managerId);

        },

        datatableId: function() { return this.id + "-dt"; },

        // Override this method to configure your view
        // This function must return a handle to the view, which is then passed
        // to the updateView method as the first argument. Because there is no
        // visualization, just return 'this'
        createView: function() {
            return this;
        },

        onFilterChange: function() {
            var status = 'status="' + this.filter.get("status").join(",") + '"';
            var type = 'type="' + this.filter.get("type").join(",") + '"';
            var analyst = 'analyst="' + this.filter.get("analyst").join(",") + '"';
            var severity = 'severity="' + this.filter.get("severity").join(",") + '"';
            var searchQuery = "| listalerts json=data "
                + status + " "
                + analyst + " "
                + severity + " "
                + type + " | table _time, type, severity, entity, status, analyst, data, kv_key";
            if (this.manager) {
                this.manager.settings.set("earliest_time", this.filter.get("earliest_time"));
                this.manager.settings.set("latest_time",this.filter.get("latest_time")); 
                this.manager.settings.set("search", searchQuery);
                this.manager.startSearch();
            }
        },

        formatResults: function(resultsModel) {
            if (!resultsModel) { return []; }
            // First try the legacy one, and if it isn't there, use the real one.
            var outputMode = this.output_mode || this.outputMode;
            var data_type = this.data_types[outputMode];
            var data = resultsModel.data();
            return this.formatData(data[data_type]);
        },

        formatExpandedRow: function(rowData) {
            //console.log('rowData', rowData);
            var alert = JSON.parse(rowData['data']);
            //console.log('alert', alert);
            var dataHtml =  _.template(
                '<div class="alert-data"><h5>Data</h5> \
                <table class="table table-condensed table-embed table-expanded table-dotted"> \
                <tbody> \
                <% for (f in alert.data) { %> \
                    <tr><td class="field-key"><%- f %></td><td class="field-value"><%- alert.data[f] %></td></tr> \
                <% } %> \
                <% if ("search_query" in alert) { \
                    var query = alert.search_query.replace(/\\s*\\|\\s*makealerts.*/,""); \
                %> \
                    <tr><td class="field-key">search query</td><td class="field-value"><a href="../search/search?q=<%- encodeURIComponent(query) %>&earliest=<%- alert.search_earliest %>&latest=<%- alert.search_latest %>" target="_blank"><%- query %></a></td></tr> \
                    <!-- <tr><td class="field-key">search earliest</td><td class="field-value"><%- alert.search_earliest %></td></tr> \
                    <tr><td class="field-key">search latest</td><td class="field-value"><%- alert.search_latest %></td></tr> --> \
                <% } %> \
                <% if (("search_name" in alert) && ("search_owner" in alert) && ("search_app" in alert)) { \
                %> \
                    <tr><td class="field-key">search name</td><td class="field-value"><a href="/manager/search/saved/searches?app=<%- encodeURIComponent(alert.search_app) %>&count=10&offset=0&itemType=&owner=<%- encodeURIComponent(alert.search_owner) %>&search=<%- encodeURIComponent(alert.search_name) %>" target="_blank"><%- alert.search_name %></a></td></tr> \
                <% } %> \
                <% if ("results_link" in alert) { \
                %> \
                    <tr><td class="field-key">search results</td><td class="field-value"><a href="<%- alert.results_link %>" target="_blank">results</a></td></tr> \
                <% } %> \
                <% if (alert.type in canned) { \
                    var a = canned[alert.type]; \
                    try { var href = _.template(a.href, {alert: alert}); } catch (err) {var href = a.href; } \
                %> \
                    <tr><td class="field-key">canned query</td><td class="field-value"><a href="<%- href %>" target="_blank"><%- a.label %></a></td></tr> \
                <% } %> \
                <% if ("sid" in alert && alert.sid.indexOf("scheduler") != -1) { \
                    var query = "index=_internal sourcetype=scheduler sid=" + alert.sid + " | head 1 | table saved*" \
                %> \
                    <tr><td class="field-key">splunk search sid</td><td class="field-value"><a href="../search/search?q=<%- encodeURIComponent(query) %>" target="_blank"><%- alert.sid %></a></td></tr> \
                <% } %> \
                </tbody> \
                </table> \
                </div>',
                { alert: alert, canned: this.settings.get("canned_queries") }
            );

            _.each(alert.work_log, function(entry) {
                entry.ftime = moment(new Date(entry.time * 1000)).format('YYYY-MM-DD HH:mm:ss');
            });

            var analysts = this.settings.get("analysts");
            var severities = this.settings.get("severities");
            var threats = Object.keys(this.settings.get("threatsToActions")).sort();
            var username = Splunk.util.getConfigValue("USERNAME");
            var table = this.table;
            var info = table.page.info();
            var recordsDisplay = info.recordsDisplay;
            var workLogHtml = _.template(
                '<div class="alert-work-log"><h5>Work Log</h5> \
                <div> \
                    <input type="checkbox" id="apply-all-<%- alert._key %>" data-action="apply-all"  >  \
                        Check to perform the action below on all <strong><span data-action="recordsDisplay"><%- recordsDisplay %></span></strong> filtered entries in the table \
                </div> \
                <% if (alert.status === "closed") { %> \
                <div> \
                    <button class="btn btn-primary submit" data-id="<%- alert._key %>" data-action="reopen">Reopen</button> \
                </div> \
                <% } else { %> \
                <div> \
                        <select id="analyst-<%- alert._key %>"> \
                            <option value="">(unassign)</option> \
                        <% _.each(analysts, function(a) { %> \
                            <% if (a === username) { %> \
                                <option value="<%- a %>" selected="true"><%- a %></option> \
                            <% } else { %> \
                                <option value="<%- a %>"><%- a %></option> \
                            <% } %> \
                        <% }); %> \
                        </select> \
                    <button class="btn btn-primary submit" data-id="<%- alert._key %>" data-action="assign">Assign</button> \
                </div> \
                <div> \
                        <select id="severity-<%- alert._key %>" data-id="<%- alert._key %>" data-action="change-severity-enabler" data-severity="<%- alert.severity %>"> \
                            <option value="">(no severity)</option> \
                        <% _.each(severities, function(a) { %> \
                            <% if (a === alert.severity) { %> \
                                <option value="<%- a %>" selected="true"><%- a %></option> \
                            <% } else { %> \
                                <option value="<%- a %>"><%- a %></option> \
                            <% } %> \
                        <% }); %> \
                        </select> \
                    <button class="btn btn-primary submit" data-id="<%- alert._key %>" data-action="change-severity" disabled=true>Change Severity</button> \
                </div> \
                <div> \
                        <select id="threat-<%- alert._key %>" data-id="<%- alert._key %>" data-action="threat"> \
                            <option value="">select threat</option> \
                        <% _.each(threats, function(a) { %> \
                            <option value="<%- a %>"><%- a %></option> \
                        <% }); %> \
                        </select> \
                        <span id="threat-action-<%- alert._key %>" data-id="<%- alert._key %>" data-action="close-enabler" style="display: inline-block; padding-bottom: 0px; vertical-align: top;"></span> \
                    <button class="btn btn-primary submit" data-id="<%- alert._key %>" data-action="close" disabled="true">Close</button> \
                </div> \
                <% } %> \
                <div> \
                        <textarea id="notes-<%- alert._key %>" rows="5" data-id="<%- alert._key %>" data-action="notes-enabler" style="width: 50%" placeholder="Notes provided here will be used on Assign/Close/Add Notes actions"></textarea> \
                    <button class="btn btn-primary submit" data-id="<%- alert._key %>" data-action="notes" disabled=true>Add Notes</button> \
                </div> \
                <table class="table table-condensed table-embed table-expanded table-dotted"> \
                <thead> \
                    <tr><th class="alert-time">Time</th><th class="alert-action">Action</th><th class="alert-analyst">Analyst</th><th class="alert-notes">Notes</th><th class="alert-worklog-data">Extra</th></tr> \
                </thead> \
                <tbody> \
                <% for(var i = 0; i < alert.work_log.length; i++) { var entry=alert.work_log[i]; %> \
                    <tr> \
                        <td class="alert-time"><%- entry.ftime %></td> \
                        <td class="alert-action"><%- entry.action %></td> \
                        <td class="alert-analyst"><%- entry.analyst %></td> \
                        <td class="alert-notes"><%- entry.notes %></td> \
                        <% if (Object.keys(entry.data).length !== 0) {%> \
                        <td class="alert-worklog-data"><%- JSON.stringify(entry.data) %></td> \
                        <% } else { %> \
                        <td class="alert-worklog-data"></td> \
                        <% } %> \
                    </tr> \
                <% } %> \
                </tbody> \
                </table></div>',
                {
                    alert: alert,
                    analysts: analysts,
                    severities: severities,
                    threats: threats,
                    username: username,
                    recordsDisplay: recordsDisplay
                }
            );

            return '<div class="alert-expanded">' + dataHtml + workLogHtml + '</div>';
        },

        // Override this method to put the Splunk data into the view
        updateView: function(viz, data) {
            // Print the data object to the console
            // console.log("The data object: ", data);
            
            function renderData(data, type, row, meta) {
                var alert = JSON.parse(data);
                var j = JSON.stringify(alert.data, null, 2);
                var safeJson = _.template("<%- j %>", {j: j});
                return safeJson;
            }

            this.$el.html('<table id="' + this.datatableId() + '" class="display table-condensed alert-table" width="100%"></table>');
            var table = $('#' + this.datatableId()).DataTable({
                data: data,
                search: { smart: false },
                columns: [
                    { className: "details-control", orderable: false, data: null, defaultContent: '<i class="icon-triangle-right-small"></i>' },
                    { title: "Time", width: "160px", data: '_time' },
                    { title: "Type", width: "160px", data: 'type' },
                    {
                        title: "Severity", data: 'severity',
                        render: function(data, type, row) {
                            if (data && data !== '') return '<span class="severity severity-' + data + '">' + data + '</span>';
                            else return "";
                        }
                    },
                    { title: "Entity", data: 'entity', defaultContent: "" },
                    { title: "Status", data: 'status' },
                    { title: "Analyst", defaultContent: "", data: 'analyst' },
                    { title: "Data (json)", data: 'data', render: renderData  }
                ],
                order: [[1, "desc"]]
            });
            this.table = table;

            table.on("search.dt", function(e, settings) {
                table.rows().every(function(idx) {
                    if (this.child()) {
                        this.child().find("[data-action=recordsDisplay]").each(function(i) {
                            $(this).html(table.page.info().recordsDisplay);
                        });
                        this.child().find("[data-action=apply-all]").each(function(i) {
                            $(this).prop('checked', false);
                        });
                    }
                });
            });

            var that = this;
            var manager = this.manager;

            // Add event listener for opening and closing details
            $('#' + this.datatableId() + ' tbody').on('click', 'td.details-control', function () {
                var tr = $(this).closest('tr');
                var row = table.row(tr);
                if (row.child.isShown()) {
                    // This row is already open - close it
                    row.child.hide();
                    tr.removeClass('shown');
                    tr.find("td.details-control").html('<i class="icon-triangle-right-small">');
                } else if (row.child()) {
                    row.child.show();
                    tr.addClass('shown');
                    tr.find("td.details-control").html('<i class="icon-triangle-down-small">');
                } else {
                    // Open this row
                    var data = row.data();
                    var key = data['kv_key'];
                    row.child(that.formatExpandedRow(data)).show();
                    var threatActionSelectId = "threat-action-" + key;
                    var threatActionSelect;
                    // clean up previous backbone view if it exists
                    if (threatActionSelectId in that.threatActionSelectMap) {
                        threatActionSelect = that.threatActionSelectMap[threatActionSelectId];
                        threatActionSelect.remove();
                    }
                    threatActionSelect = new MultiDropdownView({
                        id: threatActionSelectId,
                        managerid: null,
                        choices: [ ],
                        width: 220,
                        el: $("#" + threatActionSelectId)
                    });
                    that.threatActionSelectMap[threatActionSelectId] = threatActionSelect;
                    threatActionSelect.render();
                    threatActionSelect.on('change', function(el) {
                        var $select1 = $('select[data-action=threat][data-id=' + key + ']');
                        if (threatActionSelect.val().length > 0 && $select1.val() !== "") {
                            $('button[data-action=close][data-id=' + key + ']').prop('disabled', false);
                        } else {
                            $('button[data-action=close][data-id=' + key + ']').prop('disabled', true);
                        }
                    });

                    tr.addClass('shown');
                    tr.find("td.details-control").html('<i class="icon-triangle-down-small">');
                }
            });

            table.on('click', "[data-action='assign']", function(el) {
                var key = $(el.currentTarget).attr('data-id');
                var analyst = $('#analyst-' + key).val();
                var notes = $('#notes-' + key).val();
                var applyAll = $('#apply-all-' + key).prop('checked');
                var username = Splunk.util.getConfigValue("USERNAME");
                var keys = that.keysFromApplyAll(key);
                var entry = {
                    time: new Date().getTime()/1000,
                    action: 'assign',
                    notes: notes || username + ' assigned to ' + analyst,
                    data: {},
                    analyst: username
                };
                var status = 'assigned';
                if (analyst === "") {
                    analyst = null;
                    status = 'open';
                }
                that.updateAlerts(keys, status, analyst, undefined, entry, function(errs, responses) {
                    if (errs.length > 0) console.log('There were errors in updateAlerts', errs);
                    if (responses.length > 0) manager.startSearch();
                });
            });

            table.on('click', "[data-action='change-severity']", function(el) {
                var key = $(el.currentTarget).attr('data-id');
                var severity = $('#severity-' + key).val();
                var original = $('#severity-' + key).attr("data-severity");
                var notes = $('#notes-' + key).val();
                var applyAll = $('#apply-all-' + key).prop('checked');
                var username = Splunk.util.getConfigValue("USERNAME");
                var keys = that.keysFromApplyAll(key);
                var entry = {
                    time: new Date().getTime()/1000,
                    action: 'change-severity',
                    notes: notes || username + ' changed severity from ' + original + ' to ' + severity,
                    data: {},
                    analyst: username
                };
                that.updateAlerts(keys, undefined, undefined, severity, entry, function(errs, responses) {
                    if (errs.length > 0) console.log('There were errors in updateAlerts', errs);
                    if (responses.length > 0) manager.startSearch();
                });
            });

            table.on('click', "[data-action='close']", function(el) {
                var key = $(el.currentTarget).attr('data-id');
                var threat = $('#threat-' + key).val();
                var actionSelect = that.threatActionSelectMap['threat-action-' +  key];
                var notes = $('#notes-' + key).val();
                var username = Splunk.util.getConfigValue("USERNAME");
                var keys = that.keysFromApplyAll(key);
                var entry = {
                    time: new Date().getTime()/1000,
                    action: 'close',
                    notes: notes,
                    data: {threat: threat, actions: actionSelect.val()},
                    analyst: username
                };
                that.updateAlerts(keys, 'closed', username, undefined, entry, function(errs, responses) {
                    if (errs.length > 0) console.log('There were errors in updateAlerts', errs);
                    if (responses.length > 0) manager.startSearch();
                });
            });

            table.on('click', "[data-action='notes']", function(el) {
                var key = $(el.currentTarget).attr('data-id');
                var notes = $('#notes-' + key).val();
                var username = Splunk.util.getConfigValue("USERNAME");
                var keys = that.keysFromApplyAll(key);
                var entry = {
                    time: new Date().getTime()/1000,
                    action: 'comment',
                    notes: notes,
                    data: {},
                    analyst: username
                };
                that.updateAlerts(keys, undefined, undefined, undefined, entry, function(errs, responses) {
                    if (errs.length > 0) console.log('There were errors in updateAlerts', errs);
                    if (responses.length > 0) manager.startSearch();
                });
            });

            table.on('click', "[data-action='reopen']", function(el) {
                var key = $(el.currentTarget).attr('data-id');
                var notes = $('#notes-' + key).val();
                var username = Splunk.util.getConfigValue("USERNAME");
                var keys = that.keysFromApplyAll(key);
                var entry = {
                    time: new Date().getTime()/1000,
                    action: 're-open',
                    notes: notes,
                    data: {},
                    analyst: username
                };
                that.updateAlerts(keys, 'open', username, undefined, entry, function(errs, responses) {
                    if (errs.length > 0) console.log('There were errors in updateAlerts', errs);
                    if (responses.length > 0) manager.startSearch();
                });
            });

            // enable close button if threat and action have been selected
            table.on('change', "[data-action='threat']", function(el) {
                var $select = $(el.currentTarget);
                var key = $select.attr('data-id');
                var $select1 = $('select[data-action=close-enabler][data-id=' + key + ']');
                $('button[data-action=close][data-id=' + key + ']').prop('disabled', true);
            });

            // enable Notes button if there is actually a note
            table.on('keyup', "[data-action='notes-enabler']", function(el) {
                var $text = $(el.currentTarget);
                var key = $text.attr('data-id');
                $('button[data-action=notes][data-id=' + key + ']')
                    .prop('disabled', $text.val().trim().length <= 0);
            });

            // enable Change Severity button if it is changed
            table.on('change', "[data-action='change-severity-enabler']", function(el) {
                var $select = $(el.currentTarget);
                var key = $select.attr('data-id');
                var original = $select.attr('data-severity');
                $('button[data-action=change-severity][data-id=' + key + ']')
                    .prop('disabled', $select.val() === original);
            });

            // change actions drop down based on threat
            table.on('change', "[data-action='threat']", function(el) {
                var $select = $(el.currentTarget);
                var key = $select.attr('data-id');
                var threat = $select.val();
                var actionSelect = that.threatActionSelectMap['threat-action-' +  key];
                $('button[data-action=close][data-id=' + key + ']').prop('disabled', true);
                actionSelect.val([]);
                if (threat === "") {
                    actionSelect.settings.set("choices", []);
                } else {
                    var actions = that.settings.get("threatsToActions")[threat];
                    if (actions) {
                        var choices = $.map(actions, function(a, i) { return { label: a, value: a }; });
                        actionSelect.settings.set("choices", choices);
                    }
                }
            });
        },

        // The element should have a data-id attribute with the key and there should be a checkbox input with apply-all-key
        keysFromApplyAll: function(key) {
            var applyAll = $('#apply-all-' + key).prop('checked');
            var keys = [];
            if (applyAll) {
                this.table.rows({search: 'applied'}).every(function(idx) {
                    keys.push(this.data()['kv_key']);
                });
            } else {
                keys.push(key);
            }
            return keys;
        },

        // Update multiple alerts (requires as many round trips as there are alerts to update
        updateAlerts: function(keys, status, username, severity, entry, onComplete) {
            var completedCount = 0;
            var responses = [];
            var errs = [];
            var that = this;
            function updateCompletedCount(err, response) {
                completedCount ++;
                if (err) errs.push(err);
                if (responses) responses.push(response);
                if (completedCount === keys.length) {
                    onComplete(errs, responses);
                }
            }
            $.each(keys, function(key) {
                that.updateAlert(this, status, username, severity, entry, updateCompletedCount);
            });
        },

        // Update a single alert
        updateAlert: function(key, status, username, severity, entry, onComplete) {
            var that = this;
            this.service.request(
                "storage/collections/data/alerts/" + key,
                "GET",
                null,
                null,
                null,
                {"Content-Type": "application/json"},
                function(err, response) { 
                    if (response && 'data' in response) {
                        var record = response.data;
                        record.work_log.unshift(entry);
                        if (typeof status !== "undefined") {
                            record.status = status;
                        }
                        if (typeof username !== "undefined") {
                            record.analyst = username;
                        }
                        if (typeof severity !== "undefined") {
                            record.severity = severity;
                        }
                        that.service.request(
                            "storage/collections/data/alerts/" + key,
                            "POST",
                            null,
                            null,
                            JSON.stringify(record),
                            {"Content-Type": "application/json"},
                            function(err, response) {
                                onComplete(err, response);
                            });
                    } else {
                        onComplete(err, response);
                    }
                }
            );
        }

    });
    return S3TableView;
});

