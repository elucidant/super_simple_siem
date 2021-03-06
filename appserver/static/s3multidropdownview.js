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

define([
        "splunkjs/mvc/multidropdownview",
        'underscore',
        'jquery',
    ], function(
        MultiDropdownView,
        _,
        $
        ) {
    // Define the custom view class
    var S3MultiDropDownView = MultiDropdownView.extend(/** @lends splunkjs.mvc.MultiDropdownView.prototype */{
        className: "multidropdownview",

        // For Splunk 6.5
        convertDataToChoices: function(data) {
            //return MultiDropdownView.prototype.convertDataToChoices.apply(this, [data]);
            data = data || this._data;
            var choices = [];
            var valueField = this.settings.get("valueField") || 'value';
			if (data != null && data.length == 1) {
                var row = data[0]
                var values = row[valueField];
                if (typeof values === 'string') {
                    values = [ values ];
                }
                choices = _.map(values, function(v) {
                    return { label: v, value: v };
                });
			}
            return choices;
        },

        // For Splunk 7.1
        _updateDisplayedChoices: function(data) {
            data = data || this._data;
            var valueField = this.settings.get("valueField") || 'value';
            var labelField = this.settings.get("labelField") || valueField;

            var choices = [];
            var valueField = this.settings.get("valueField") || 'value';
			if (data != null && data.length == 1) {
                var row = data[0]
                var values = row[valueField];
                if (typeof values === 'string') {
                    values = [ values ];
                }
                choices = _.map(values, function(v) {
                    return { label: v, value: v };
                });
			}
            this._displayedChoices = choices;

            this._handleSelectFirstChoice();
            this.updateSelectedLabel();
        }
    });

    return S3MultiDropDownView;
});

