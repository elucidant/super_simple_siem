/*
Copyright 2022 Jean-Laurent Huynh

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
require([
    "splunkjs/mvc",
    "jquery",
    "splunkjs/mvc/simpleform/input/timerange",
    "splunkjs/mvc/searchmanager",
    "/static/app/super_simple_siem/s3tableview.js",
    "/static/app/super_simple_siem/s3multidropdownview.js",
    "splunkjs/mvc/simplexml/ready!"
    ],
    function(
        mvc,
        $,
        TimeRangeInput,
        SearchManager,
        S3TableView,
        S3MultiDropdownView,
        UrlTokenModel
        ) {

        //
        // TOKENS
        //

        // Create token namespaces
        var defaultTokenModel = mvc.Components.getInstance('default', {create: true});
        var submittedTokenModel = mvc.Components.getInstance('submitted', {create: true});

        // Convert attributes that should be arrays
        function promoteTokenToArray(tokenName) {
            var tok = defaultTokenModel.get(tokenName)
            if (!tok) {
                defaultTokenModel.set(tokenName, []);
            } else if (typeof tok === 'string') {
                defaultTokenModel.set(tokenName, [ tok ]);
            }
        }
        promoteTokenToArray("form.status");
        promoteTokenToArray("form.type");
        promoteTokenToArray("form.analyst");
        promoteTokenToArray("form.severity");

        function syncTokens() {
            // Copy the contents of the defaultTokenModel to the URL query params
            const tokens = defaultTokenModel.toJSON();
            if (window.history.pushState) {
				// Construct URLSearchParams object instance from current URL querystring.
				var queryParams = new URLSearchParams([]);
				for (const [k, v] of Object.entries(tokens)) {
					if (k.startsWith("form.")) {
                        if (Array.isArray(v)) {
                            queryParams.delete(v);
                            for (const e of v) {
                                queryParams.append(k, e);
                            }
                        } else {
                            queryParams.set(k, v);
                        }
                    }
				}
				window.history.pushState(null, null, "?"+queryParams.toString());
            }
        }

        //
        // SEARCH MANAGERS
        //
        var filterChoicesSearch = new SearchManager({
            id: "filter-choices",
            search: "| listalerts | fields status, analyst, type, severity | stats values(*) as \"*\"",
            preview: true,
            cache: true
        });

        //
        // VIEWS: FORM INPUTS
        //

        // Instantiate components

        var timeinput = new TimeRangeInput({
            "id": "timeinput",
            "searchWhenChanged": false,
            "default": {"form.latest_time": null, "form.earliest_time": null},
            "earliest_time": "$form.earliest_time$",
            "latest_time": "$form.latest_time$",
            "el": $('#timeinput')
        }, {tokens: true}).render();

        var statusDropDown = new S3MultiDropdownView({
            id: "statusdropdown",
            managerid: "filter-choices",
            width: 400,
            default: [ "assigned", "open"],
            valueField: "status",
            value: mvc.tokenSafe("$form.status$"),
            el: $("#statusdropdown")
        }, {tokens: true}).render();

        var typeDropDown = new S3MultiDropdownView({
            id:"view-typedropdown",
            managerid: "filter-choices",
            valueField: "type",
            default: [],
            width: 800,
            value: mvc.tokenSafe("$form.type$"),
            el: $("#typedropdown")
        }, {tokens: true}).render();

        var analystDropDown = new S3MultiDropdownView({
            id:"view-analystdropdown",
            managerid: "filter-choices",
            valueField: "analyst",
            default: [],
            width: 800,
            value: mvc.tokenSafe("$form.analyst$"),
            el: $("#analystdropdown")
        }, {tokens: true}).render();

        var severityDropDown = new S3MultiDropdownView({
            id:"view-severitydropdown",
            managerid: "filter-choices",
            labelField: "Severity",
            valueField: "severity",
            default: [],
            width: 800,
            value: mvc.tokenSafe("$form.severity$"),
            el: $("#severitydropdown")
        }, {tokens: true}).render();

        var s3tableview = new S3TableView({
            id: "s3tableview",
            el: $("#s3tableview")
        });

        s3tableview.filter.set("status", defaultTokenModel.get("form.status"));
        s3tableview.filter.set("type", defaultTokenModel.get("form.type"));
        s3tableview.filter.set("analyst", defaultTokenModel.get("form.analyst"));
        s3tableview.filter.set("severity", defaultTokenModel.get("form.severity"));
        s3tableview.filter.set("earliest_time", defaultTokenModel.get("form.earliest_time"));
        s3tableview.filter.set("latest_time", defaultTokenModel.get("form.latest_time"));
        s3tableview.render();

        defaultTokenModel.on("change:form.status", function() {
            s3tableview.filter.set("status", defaultTokenModel.get("form.status"));
            syncTokens();
        });
        defaultTokenModel.on("change:form.type", function() {
            s3tableview.filter.set("type", defaultTokenModel.get("form.type"));
            syncTokens();
        });
        defaultTokenModel.on("change:form.analyst", function() {
            s3tableview.filter.set("analyst", defaultTokenModel.get("form.analyst"));
            syncTokens();
        });
        defaultTokenModel.on("change:form.severity", function() {
            s3tableview.filter.set("severity", defaultTokenModel.get("form.severity"));
            syncTokens();
        });

        timeinput.on("change", function(newValue) {
            s3tableview.filter.set("earliest_time", defaultTokenModel.get("form.earliest_time"));
            s3tableview.filter.set("latest_time", defaultTokenModel.get("form.latest_time"));
            syncTokens();
        });

        // Initialize time tokens to default
        if (!defaultTokenModel.has("form.status") || defaultTokenModel.get("form.status").length === 0) {
            defaultTokenModel.set("form.status", ["open", "assigned"]);
        }
        syncTokens();

    }
);
