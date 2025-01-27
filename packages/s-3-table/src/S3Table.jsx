import React, { useState, useEffect} from 'react';
import PropTypes from 'prop-types';
import Button from '@splunk/react-ui/Button';
import ColumnLayout from '@splunk/react-ui/ColumnLayout';
import ControlGroup from '@splunk/react-ui/ControlGroup';
import Heading from '@splunk/react-ui/Heading';
import Message from '@splunk/react-ui/Message';
import MessageBar from '@splunk/react-ui/MessageBar';
import Multiselect from '@splunk/react-ui/Multiselect';
import Paginator from '@splunk/react-ui/Paginator';
import Table from '@splunk/react-ui/Table';
import TextArea from '@splunk/react-ui/TextArea';
import Text from '@splunk/react-ui/Text';
import Select from '@splunk/react-ui/Select';
import StaticContent from '@splunk/react-ui/StaticContent';
import Switch from '@splunk/react-ui/Switch';
import SplunkwebConnector from '@splunk/react-time-range/SplunkwebConnector';
import TimeRangeDropdown from '@splunk/react-time-range/Dropdown';
import SearchJob from '@splunk/search-job';
import getTheme from '@splunk/themes/getTheme';
import * as config from '@splunk/splunk-utils/config';
import { createRESTURL } from '@splunk/splunk-utils/url';
import { findErrorMessage, getDefaultFetchInit } from '@splunk/splunk-utils/fetch';
import moment from '@splunk/moment';
import { Severity } from './S3TableStyles';


// Store some form state in global variables between unmount and mount of the expansion row.
// This preserves the notes and close threat/actions when toggling row expansion.
window.s3Notes = {};
window.s3Close = {};

// For interpolating the alert data into the canned queries href field.
function deferenceField(alert, fieldRef) {
    const elements = fieldRef.trim().split(".").map(e => e.trim());
    if (elements.length < 2) {
        return null;
    }
    if (elements[0] !== "alert") {
        return null;
    }
    let value = alert;
    for (const e of elements.slice(1)) {
        if (e in value) {
            value = value[e];
        } else {
            return null;
        }
    }
    return value;
}

// Originally a underscore template fragment, search for the <%- %> placeholder and interpolate with alert data.
// If the field does not exist, leave the placeholder as is.
function interpolateAlertData(href, alert) {
    // href is a string with <%- alert.field %> or <%- alert.data.field %> to be replaced with alert data.
    // Use regular expressions to get the strings segments before and after the <%- %> tags
    const placeholder = /<%-([^%]*)%>/g;
    let result = "";
    let cursorAt = 0;
    for (let m = placeholder.exec(href); m !== null; m = placeholder.exec(href)) {
        const [chunk, fieldRef] = m;
        // append what's before the match
        result += href.substring(cursorAt, placeholder.lastIndex - chunk.length);
        const value = deferenceField(alert, fieldRef);
        if (value !== null) {
            result += value;
        } else {
            result += chunk;
        }
        cursorAt = placeholder.lastIndex;
    }
    // append anything at the end
    result += href.substring(cursorAt);
    return result;
}

// On a search cluster behind a load balancer, this will allow linking to the load balancer rather than the search head.
function removeHost(url) {
    let u = new URL(url);
    return u.pathname + u.search;
}


function ExpansionRow({row, filteredData, allAnalysts, allSeverities, cannedQueries, threatsToActions,
    onReopenClick, onAssignClick, onUnassignClick, onChangeSeverityClick, onCloseClick, onAddNotesClick,
    theme, userTheme, odd}) {
    const [batchUpdate, setBatchUpdate] = useState(false);
    const [assignToAnalyst, setAssignToAnalyst] = useState(row.status === "assigned" ? row.analyst : config.username);
    const [newSeverity, setNewSeverity] = useState(row.severity);
    const [enteredThreat, setEnteredThreat] = useState(row.kv_key in window.s3Close ? window.s3Close[row.kv_key].enteredThreat : "select threat");
    const [enteredActions, setEnteredActions] = useState(row.kv_key in window.s3Close ? window.s3Close[row.kv_key].enteredActions : []);
    const [notes, setNotes] = useState(row.kv_key in window.s3Notes ? window.s3Notes[row.kv_key] : "");
    const alert = JSON.parse(row.data);

    useEffect(() => {
        return () => {
            window.s3Notes[row.kv_key] = notes;
        };
    }, [notes]);

    useEffect(() => {
        return () => {
            window.s3Close[row.kv_key] = {enteredThreat, enteredActions};
        };
    }, [enteredThreat, enteredActions]);


    function onBatchUpdateClick(ev) {
        setBatchUpdate(!batchUpdate);
    }
    function onAssignToAnalystChange(ev, {value}) {
        setAssignToAnalyst(value);
    }
    function onThreatChange(ev, {value}) {
        setEnteredThreat(value || "select threat");
        setEnteredActions([]);
    }
    function onActionsChange(ev, {values}) {
        setEnteredActions(values);
    }
    function clear() {
        setEnteredThreat("select threat");
        setEnteredActions([]);
        setNotes("");
    }

    const searchQuery = "search_query" in alert ? alert.search_query.replace(/\s*\|\s*makealerts.*/,"") : "";
    const canned = alert.type in cannedQueries ? cannedQueries[alert.type] : null;
    const cannedHref = canned !== null ? interpolateAlertData(canned.href, alert) : null;

    const rowStyle = userTheme === "light" ? {backgroundColor: odd ? theme.gray96 : null} : {backgroundColor: odd ? theme.gray20 : theme.gray22};

    // only allow batch update if there isn't a mixed of closed and non-closed alerts
    const batchUpdateDisabled = filteredData.some(row => row.status === "closed") && filteredData.some(row => row.status !== "closed");

    return (
        <Table.Row key={`${row.kv_key}-expansion`}>
            <Table.Cell style={{ ...rowStyle, borderTop: 'none' }} colSpan={7}>
                <div style={rowStyle}>
                    <Heading level={5}>Data</Heading>
                    <table style={{width: '100%', fontSize: '12px', lineHeight: '14px', borderSpacing: '0', borderColor: 'darkgray', borderStyle: 'dotted', padding: '5px', borderWidth: '2px'}}>
                        <tbody>
                            {Object.entries(alert.data).map(([key, value]) => (
                                <tr key={`${row.kv_key}-${key}`}>
                                    <td style={{width: '130px', borderTop: '1px solid #ddd', padding: '2px 3px', lineHeight: '20px'}}>{key}</td>
                                    <td style={{borderTop: '1px solid #ddd', padding: '2px 3px'}}>{value}</td>
                                </tr>
                            ))}
                            { searchQuery ? (
                                <tr>
                                    <td style={{width: '130px', borderTop: '1px solid #ddd', padding: '2px 3px', lineHeight: '20px'}}>search query</td>
                                    <td style={{borderTop: '1px solid #ddd', padding: '2px 3px'}}>
                                        <a href={ `../search/search?q=${encodeURIComponent(searchQuery)}&earliest=${alert.search_earliest}&latest=${alert.search_latest}`} target="_blank" style={{color: theme.linkColor}}>{searchQuery}</a>
                                    </td>
                                </tr>
                            ) : null}
                            {(("search_name" in alert) && ("search_owner" in alert) && ("search_app" in alert)) ? (
                                <tr>
                                    <td style={{width: '130px', borderTop: '1px solid #ddd', padding: '2px 3px', lineHeight: '20px'}}>search name</td>
                                    <td style={{borderTop: '1px solid #ddd', padding: '2px 3px'}}>
                                        <a href={ `/manager/search/saved/searches?app=${encodeURIComponent(alert.search_app)}&count=10&offset=0&owner=${encodeURIComponent(alert.search_owner)}&search=${encodeURIComponent(alert.search_name)}` } target="_blank" style={{color: theme.linkColor}}>{alert.search_name}</a>
                                    </td>
                                </tr>
                            ) : null}
                            {"results_link" in alert ? (
                                <tr>
                                    <td style={{width: '130px', borderTop: '1px solid #ddd', padding: '2px 3px', lineHeight: '20px'}}>search results</td>
                                    <td style={{borderTop: '1px solid #ddd', padding: '2px 3px'}}>
                                        <a href={removeHost(alert.results_link)} target="_blank" style={{color: theme.linkColor}}>results</a>
                                    </td>
                                </tr>
                            ) : null}
                            {canned !== null ? (
                                <tr>
                                    <td style={{width: '130px', borderTop: '1px solid #ddd', padding: '2px 3px', lineHeight: '20px'}}>canned query</td>
                                    <td style={{borderTop: '1px solid #ddd', padding: '2px 3px'}}>
                                        <a href={cannedHref} target="_blank" style={{color: theme.linkColor}}>{canned.label}</a>
                                    </td>
                                </tr>
                            ) : null}
                            {("sid" in alert && alert.sid.indexOf("scheduler") !== 1) ? (
                                <tr>
                                    <td style={{width: '130px', borderTop: '1px solid #ddd', padding: '2px 3px', lineHeight: '20px'}}>splunk search sid</td>
                                    <td style={{borderTop: '1px solid #ddd', padding: '2px 3px'}}>
                                        <a href={`../search/search?q=${encodeURIComponent(`index=_internal sourcetype=scheduler sid=${alert.sid} | head 1 | table saved*`)}&earliest=${alert.work_log.slice(-1).pop().time}`} target="_blank" style={{color: theme.linkColor}}>{alert.sid}</a>
                                    </td>
                                </tr>
                            ) : null}
                        </tbody>
                    </table>
                    <Heading level={5}>Work Log</Heading>
                    <div style={{marginBottom: '5px', borderColor: 'darkgray', borderStyle: 'dotted', padding: '5px', borderWidth: '2px'}}>
                        <ControlGroup label="Batch update">
                            <Switch disabled={batchUpdateDisabled} selected={batchUpdate} onClick={onBatchUpdateClick} appearance='checkbox' />
                            <StaticContent>{batchUpdateDisabled ? "Batch update is not allowed if visible alerts have closed and non-closed status" : `Check box to perform on ${filteredData.length} filtered alert(s)`}</StaticContent>
                        </ControlGroup>
                        {(row.status === "closed") ?
                            (
                                <ControlGroup
                                    label="Notes"
                                    help="Notes to be added to the work log">
                                    <TextArea value={notes} onChange={(ev, { value }) => setNotes(value)} />;
                                    <Button label="Reopen" appearance="primary" onClick={() => { onReopenClick(row, batchUpdate, notes); clear(); }} />
                                </ControlGroup>
                            ) : (
                                <>
                                    <ControlGroup
                                        label="Assign">
                                        <Select value={assignToAnalyst} onChange={onAssignToAnalystChange} style={{ width: '100px' }}>
                                            {allAnalysts.map((s) => (
                                                <Select.Option key={s} label={s} value={s} />
                                            ))}
                                        </Select>
                                        <Button disabled={assignToAnalyst === row.analyst} label="Assign" appearance="primary" onClick={() => {onAssignClick(row, batchUpdate, notes, assignToAnalyst); clear(); }} />
                                        <Button disabled={row.status !== "assigned"} label="Unassign" appearance="primary" onClick={() => {onUnassignClick(row, batchUpdate, notes); clear(); }} />
                                    </ControlGroup>
                                    <ControlGroup
                                        label="Severity">
                                        <Select value={newSeverity} onChange={(ev, { value }) => setNewSeverity(value)} style={{ width: '100px' }}>
                                            {allSeverities.map((s) => (
                                                <Select.Option key={s} label={s} value={s} />
                                            ))}
                                        </Select>
                                        <Button disabled={newSeverity === row.severity} label="Change Severity" onClick={() => {onChangeSeverityClick(row, batchUpdate, notes, newSeverity); clear(); }} />
                                    </ControlGroup>
                                    <ControlGroup
                                        label="Close">
                                        <Select value={enteredThreat} onChange={onThreatChange} style={{ width: '180px' }}>
                                            {Object.keys(threatsToActions).toSorted().map((s) => (
                                                <Select.Option key={s} label={s} value={s} />
                                            ))}
                                        </Select>
                                        <Multiselect values={enteredActions} onChange={onActionsChange} style={{ width: '200px' }}>
                                            {threatsToActions[enteredThreat].map((s) => (
                                                <Multiselect.Option key={s} label={s} value={s} />
                                            ))}
                                        </Multiselect>
                                        <Button disabled={!enteredThreat || enteredActions.length === 0} label="Close" appearance="primary" onClick={() => { onCloseClick(row, batchUpdate, notes, enteredThreat, enteredActions); clear() }} />
                                    </ControlGroup>
                                    <ControlGroup
                                        label="Notes"
                                        help="Notes to be added to the work log">
                                        <TextArea value={notes} onChange={(ev, { value }) => setNotes(value)} />;
                                        <Button disabled={notes.trim().length <= 0} label="Add Notes" onClick={() => { onAddNotesClick(row, batchUpdate, notes); clear(); }} />
                                    </ControlGroup>
                                </>)
                        }
                        <table style={{width: '100%', fontSize: '12px', lineHeight: '14px', borderSpacing: '0'}}>
                            <thead>
                                <tr>
                                    <th style={{width: '140px', borderBottom: '1px solid #111'}}>Time</th>
                                    <th style={{width: '100px', borderBottom: '1px solid #111'}}>Action</th>
                                    <th style={{width: '140px', borderBottom: '1px solid #111'}}>Analyst</th>
                                    <th style={{minWidth: '300px', borderBottom: '1px solid #111'}}>Notes</th>
                                    <th style={{borderBottom: '1px solid #111'}}>Extra</th>
                                </tr>
                            </thead>
                            <tbody>
                                {alert.work_log.map((wl, idx) => (
                                    <tr key={`${row.kv_key}-wl-${idx}`}>
                                        <td style={{borderTop: '1px solid #ddd', padding: '2px 3px', lineHeight: '20px'}}>{moment(new Date(wl.time * 1000)).format('YYYY-MM-DD HH:mm:ss')}</td>
                                        <td style={{borderTop: '1px solid #ddd', padding: '2px 3px', lineHeight: '20px'}}>{wl.action}</td>
                                        <td style={{borderTop: '1px solid #ddd', padding: '2px 3px', lineHeight: '20px'}}>{wl.analyst}</td>
                                        <td style={{borderTop: '1px solid #ddd', padding: '2px 3px', lineHeight: '20px', whiteSpace: 'pre-wrap'}}>{wl.notes}</td>
                                        <td style={{borderTop: '1px solid #ddd', padding: '2px 3px', lineHeight: '20px'}}>{wl.data && JSON.stringify(wl.data)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </Table.Cell>
        </Table.Row>
    );
}

const S3Table = ({ userTheme }) => {

    const [multiselectAreLoading, setMultiselectAreLoading] = useState(true);

    const statuses = ["open", "assigned", "closed"];
    const defaultStatuses = statuses.slice(0, 2);
    const [allAnalysts, setAllAnalysts] = useState([]);
    const [allSeverities, setAllSeverities] = useState([]);
    const [cannedQueries, setCannedQueries] = useState({});
    const [threatsToActions, setThreatsToActions] = useState({});

    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);

    const [earliest, setEarliest] = useState(urlParams.has("earliest") ? urlParams.get("earliest") : "0");
    const [latest, setLatest] = useState(urlParams.has("latest") ? urlParams.get("latest") : "now");

    const [types, setTypes] = useState([]);
    const [severities, setSeverities] = useState([]);
    const [analysts, setAnalysts] = useState([]);

    const [selectedStatuses, setSelectedStatuses] = useState(urlParams.has("status") ? urlParams.getAll("status") : defaultStatuses);
    const [selectedTypes, setSelectedTypes] = useState(urlParams.has("type") ? urlParams.getAll("type") : []);
    const [selectedSeverities, setSelectedSeverities] = useState(urlParams.has("severity") ? urlParams.getAll("severity") : []);
    const [selectedAnalysts, setSelectedAnalysts] = useState(urlParams.has("analyst") ? urlParams.getAll("analyst") : []);

    const [tableData, setTableData] = useState([]);
    const [displaySearchFilter, setDisplaySearchFilter] = useState("");
    const [pageNum, setPageNum] = useState(1);
    const [sortKey, setSortKey] = useState("_time");
    const [sortDir, setSortDir] = useState("desc");
    const [itemsPerPage, setItemsPerPage] = useState("10");
    const [expandedInfo, setExpandedInfo] = useState({});

    const regex = new RegExp(displaySearchFilter, "i");
    const filteredData = tableData.filter(row => regex.test(row.data));
    const pageNumMax = Math.ceil(filteredData.length / itemsPerPage);
    const visibleTableData = filteredData.slice((pageNum - 1) * itemsPerPage, pageNum * itemsPerPage);

    // increment this to for a table data reload
    const [changeCounter, setChangeCounter] = useState(0);

    const [warnings, setWarnings] = useState([]);

    const kvUrl = createRESTURL(`storage/collections/data/alerts`, {
        app: config.app,
        sharing: 'app',
    });

    // the user theme
    const theme = getTheme({ family: 'enterprise', colorScheme: userTheme !== null ? userTheme : "light" });

    function handleSort(ev, { sortKey: newSortKey }) {
        // defaults to "asc" except for Time
        var newSortDir = "_time" === newSortKey ? "desc" : "asc";
        // if sortKey has not changed, flips direction
        if (newSortKey === sortKey) {
            newSortDir = sortDir === 'asc' ? 'desc' : 'asc';
        }
        setSortDir(newSortDir);
        setSortKey(newSortKey);
        setTableData(tableData.sort((a, b) => {
            if (newSortDir === 'asc') {
                return a[newSortKey] > b[newSortKey] ? 1 : -1;
            } else {
                return a[newSortKey] < b[newSortKey] ? 1 : -1;
            }
        }));
    }

    function handlePageNumChange(ev, { page }) {
        setPageNum(page);
    }

    function onDisplaySearchFilterChange(ev, { value }) {
        setDisplaySearchFilter(value);
        setPageNum(1);
    }

    function onTimeRangeChange(e, { earliest: a, latest: b }) {
        setEarliest(a);
        setLatest(b);
    }

    function onStatusChange(ev, { values }) {
        setSelectedStatuses(values);
    }

    function onTypeChange(ev, { values }) {
        setSelectedTypes(values);
    }

    function onSeverityChange(ev, { values }) {
        setSelectedSeverities(values);
    }

    function onAnalystChange(ev, { values }) {
        setSelectedAnalysts(values);
    }

    function ensureArray(input) {
        return (Array.isArray(input)) ? input : [input];
    }

    useEffect(() => {
        // sync form parameters to the URL parameters
        if (window.history.pushState) {
            // Construct query parameters to save state of dropdown
            const params = [];
            params.push(`earliest=${encodeURIComponent(earliest)}`);
            params.push(`latest=${encodeURIComponent(latest)}`);
            for (const e of selectedStatuses) {
                params.push(`status=${encodeURIComponent(e)}`);
            }
            for (const e of selectedTypes) {
                params.push(`type=${encodeURIComponent(e)}`);
            }
            for (const e of selectedSeverities) {
                params.push(`severity=${encodeURIComponent(e)}`);
            }
            for (const e of selectedAnalysts) {
                params.push(`analyst=${encodeURIComponent(e)}`);
            }
            const queryParams = params.join("&");
            window.history.pushState(null, null, `?${queryParams}`);
        } else {
            setWarnings([...warnings, "Unable to save form state as URL parameters"]);
        }
    }, [earliest, latest, selectedStatuses, selectedTypes, selectedSeverities, selectedAnalysts]);

    useEffect(() => {
        const mySearchJob = SearchJob.create({
            search: `| listalerts | fields analyst, type, severity | stats values(*) as "*"`,
            earliest_time: '0',
            latest_time: 'now',
        }, {
            cache: true,
            app: config.app,
            sharing: "app",
        });

        const resultsSubscription = mySearchJob.getResults().subscribe(results => {
            console.log("MultiSelect options", results);
            if (results.results && results.results.length > 0) {
                setSeverities(ensureArray(results.results[0].severity));
                setTypes(ensureArray(results.results[0].type));
                setAnalysts(ensureArray(results.results[0].analyst));
            } else {
                setWarnings([...warnings, `Unable to retrieve multi select options: ${JSON.stringify(results)}`]);
            }
            setMultiselectAreLoading(false);
        });
    }, []);

    useEffect(() => {
        const mySearchJob = SearchJob.create({
            search: `| inputlookup analysts`,
            earliest_time: '0',
            latest_time: 'now',
        }, {
            app: config.app,
            sharing: "app",
        });

        mySearchJob.getResults().subscribe(results => {
            if (results.results) {
                const arr = results.results.map(r => r.analyst);
                setAllAnalysts(arr);
            } else {
                setWarnings([...warnings, `No analysts found: ${results}`]);
            }
        });
    }, []);

    useEffect(() => {
        const mySearchJob = SearchJob.create({
            search: `| inputlookup severities`,
        }, {
            app: config.app,
            sharing: "app",
        });

        mySearchJob.getResults().subscribe(results => {
            if (results.results) {
                const arr = results.results.map(r => r.severity);
                setAllSeverities(arr);
            } else {
                setWarnings([...warnings, `No severities found: ${results}`]);
            }
        });
    }, []);

    useEffect(() => {
        const mySearchJob = SearchJob.create({
            search: `| inputlookup canned_queries`,
            earliest_time: '0',
            latest_time: 'now',
        }, {
            app: config.app,
            sharing: "app",
        });

        mySearchJob.getResults().subscribe(results => {
            const typesToCanned = {};
            if (results.results) {
                results.results.forEach(result => typesToCanned[result.type] = result);
                setCannedQueries(typesToCanned);
            } else {
                setWarnings([...warnings, `No canned queries found: ${results}`]);
            }
        });
    }, []);


    useEffect(() => {
        const mySearchJob = SearchJob.create({
            search: '| inputlookup threats_to_actions | table Threat, Actions',
            earliest_time: '0',
            latest_time: 'now',
        }, {
            app: config.app,
            sharing: "app",
        });

        mySearchJob.getResults().subscribe(results => {
            const threats = { "select threat": [] };
            if (results.results) {
                results.results.forEach(result => threats[result.Threat] = result.Actions.split(","));
                setThreatsToActions(threats);
            } else {
                setWarnings([...warnings, `No threats_to_actions found: ${results}`]);
            }
        });
    }, []);

    function fmtChoices(selections) {
        const text = selections.join(",");
        return text.replace(/"/g, '\\"');
    }

    useEffect(() => {
        if (!multiselectAreLoading) {
            console.log("Reloading table from KV store", earliest, latest, selectedStatuses, selectedTypes, selectedSeverities, selectedAnalysts, changeCounter);
            const spl = `| listalerts json=data
            status="${fmtChoices(selectedStatuses)}"
            type="${fmtChoices(selectedTypes)}"
            analyst="${fmtChoices(selectedAnalysts)}"
            severity="${fmtChoices(selectedSeverities)}"
            | table _time, type, severity, entity, status, analyst, data, kv_key`;
            const mySearchJob = SearchJob.create({
                search: spl,
                earliest_time: earliest,
                latest_time: latest,
            }, {
                app: config.app,
                sharing: "app",
            });

            const resultsSubscription = mySearchJob.getResults({ count: 0 }).subscribe(results => {
                setTableData(results.results);
                setDisplaySearchFilter("");
            });
        }
    }, [multiselectAreLoading, selectedStatuses, selectedTypes, selectedSeverities, selectedAnalysts, earliest, latest, changeCounter]);

    // Update the alert, returns null or an error message
    async function updateAlert(row, status, username, severity, entry) {
        const kv_key = row.kv_key;
        const fetchInit = getDefaultFetchInit();
        fetchInit.method = 'GET';
        const response = await fetch(`${kvUrl}/${kv_key}`, {
            ...fetchInit,
            headers: {
                'X-Splunk-Form-Key': config.getCSRFToken(),
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/json',
            },
        })
        if (!response.ok) {
            const error = findErrorMessage(response);
            return error;
        }
        const alert = JSON.parse(row.data);
        const record = await response.json();
        if (record.work_log.length !== alert.work_log.length) {
            return "Alert has been updated by another user";
        }
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
        fetchInit.method = 'POST';
        const updateResponse = await fetch(`${kvUrl}/${kv_key}`, {
            ...fetchInit,
            headers: {
                'X-Splunk-Form-Key': config.getCSRFToken(),
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(record),
        })
        if (!updateResponse.ok) {
            return findErrorMessage(updateResponse);
        }
        return null;
    }

    // Batch update, return a dict from object kv_keys to their update error message (null if no error).
    async function updateAlerts(rows, status, username, severity, entry) {
        const updateStatus = {};
        const batchUpdateCode = (new Date()).toJSON();
        const entryWithBatch = rows.length > 1 ? {...entry, notes: `${entry.notes}\n[batch update code: ${batchUpdateCode}]`} : entry;
        for (const row of rows) {
            const error = await updateAlert(row, status, username, severity, entryWithBatch);
            updateStatus[row.kv_key] = error;
            if (error !== null) {
                setWarnings([...warnings, `Error updating ${row.kv_key}: ${error}`]);
            }
        }
        return updateStatus;
    }

    function newWorkLogEntry(action, notes) {
        return {
            time: new Date().getTime() / 1000,
            action,
            notes,
            data: {},
            analyst: config.username
        };
    }

    function refreshTable() {
        setDisplaySearchFilter("");
        setChangeCounter(changeCounter + 1);
        window.s3Notes = {};
        window.s3Close = {};
        setExpandedInfo({});
    }

    function handleReopenClick(row, batchUpdate, notes) {
        const entry = newWorkLogEntry('re-open', notes);
        const rows = batchUpdate ? filteredData : [row];
        updateAlerts(rows, "open", config.username, undefined, entry);
        refreshTable();
    }

    function handleAssignClick(row, batchUpdate, notes, analyst) {
        const rows = batchUpdate ? filteredData : [row];
        const entry = {
            ...newWorkLogEntry('assign', notes),
            notes: notes || `${config.username} assigned to ${analyst}`
        };
        updateAlerts(rows, 'assigned', analyst, undefined, entry);
        refreshTable();
    }

    function handleUnassignClick(row, batchUpdate, notes) {
        const rows = batchUpdate ? filteredData : [row];
        const entry = {
            ...newWorkLogEntry('open', notes),
            notes: notes || `${config.username} unassigned alert`
        };
        updateAlerts(rows, 'open', null, undefined, entry);
        refreshTable();
    }

    function handleChangeSeverityClick(row, batchUpdate, notes, newSeverity) {
        const rows = batchUpdate ? filteredData : [row];
        const entry = {
            ...newWorkLogEntry('change-severity'),
            notes: notes || `${config.username} changed severity from ${row.severity} to ${newSeverity}`
        };
        updateAlerts(rows, undefined, undefined, newSeverity, entry);
        refreshTable();
    }

    function handleCloseClick(row, batchUpdate, notes, threat, actions) {
        const rows = batchUpdate ? filteredData : [row];
        const entry = {
            ...newWorkLogEntry('close', notes),
            data: { threat, actions },
        };
        updateAlerts(rows, 'closed', config.username, undefined, entry);
        refreshTable();
    }

    function handleAddNotesClick(row, batchUpdate, notes) {
        const rows = batchUpdate ? filteredData : [row];
        const entry = newWorkLogEntry('comment', notes);
        // TODO check whether we need to preserve the analyst on batch calls
        updateAlerts(rows, undefined, row.analyst, undefined, entry);
        refreshTable();
    }

    function getExpansionRow(row, odd) {
        return (
            <ExpansionRow row={row}
                filteredData={filteredData}
                allAnalysts={allAnalysts}
                allSeverities={allSeverities}
                cannedQueries={cannedQueries}
                threatsToActions={threatsToActions}
                onReopenClick={handleReopenClick}
                onAssignClick={handleAssignClick}
                onUnassignClick={handleUnassignClick}
                onChangeSeverityClick={handleChangeSeverityClick}
                onCloseClick={handleCloseClick}
                onAddNotesClick={handleAddNotesClick}
                theme={theme}
                userTheme={userTheme}
                odd={odd}
            ></ExpansionRow>
        );
    }

    function handleOnExpansion(row) {
        // new entry value:
        const rowExpandedInfo = row.kv_key in expandedInfo ? expandedInfo[row.kv_key] : {expanded: false};
        // flip the expanded value
        const updatedRowExpandedInfo = { ...rowExpandedInfo, expanded: !rowExpandedInfo.expanded };
        const newExpandedInfo = { ...expandedInfo, [row.kv_key]: updatedRowExpandedInfo };
        setExpandedInfo(newExpandedInfo);
    }

    if (multiselectAreLoading) {
        return (
        <div style={{backgroundColor: theme.backgroundColor, paddingTop: '2px'}}>
            <Message type="info">Loading filter options...</Message>
        </div>
        );
    } else {
        return (
            <div style={{backgroundColor: theme.backgroundColor, paddingTop: '2px'}}>
                {
                    (warnings.length > 0) ? (
                        <MessageBar type="warning" onRequestClose={() => {setWarnings([]);}}>
                            <ul>
                                {warnings.map((w, idx) => (
                                    <li key={idx}>{w}</li>
                                ))}
                            </ul>
                        </MessageBar>
                    ) : null
                }
                <ColumnLayout>
                    <ColumnLayout.Row>
                        <ColumnLayout.Column span={2}>
                            Time Range<br />
                            <SplunkwebConnector>
                                <TimeRangeDropdown
                                    onChange={onTimeRangeChange}
                                    earliest={earliest}
                                    latest={latest}
                                    realTimeDisabled
                                />
                            </SplunkwebConnector>
                        </ColumnLayout.Column>
                        <ColumnLayout.Column span={2}>
                            Status<br />
                            <Multiselect onChange={onStatusChange} defaultValues={selectedStatuses}>
                                {statuses.map((s) => (
                                    <Multiselect.Option key={s} label={s} value={s} />
                                ))}
                            </Multiselect>
                        </ColumnLayout.Column>
                        <ColumnLayout.Column span={2}>
                            Type<br />
                            <Multiselect onChange={onTypeChange} defaultValues={selectedTypes}>
                                {types.map((s) => (
                                    <Multiselect.Option key={s} label={s} value={s} />
                                ))}
                            </Multiselect>
                        </ColumnLayout.Column>
                        <ColumnLayout.Column span={2}>
                            Severity<br />
                            <Multiselect onChange={onSeverityChange} defaultValues={selectedSeverities}>
                                {severities.map((s) => (
                                    <Multiselect.Option key={s} label={s} value={s} />
                                ))}
                            </Multiselect>
                        </ColumnLayout.Column>
                        <ColumnLayout.Column span={2}>
                            Analyst<br />
                            <Multiselect onChange={onAnalystChange} defaultValues={selectedAnalysts}>
                                {analysts.map((s) => (
                                    <Multiselect.Option key={s} label={s} value={s} />
                                ))}
                            </Multiselect>
                        </ColumnLayout.Column>
                        <ColumnLayout.Column span={2} />
                    </ColumnLayout.Row>
                    <ColumnLayout.Row>
                        <ColumnLayout.Column span={6}>
                            <Paginator
                                onChange={handlePageNumChange}
                                current={pageNum}
                                alwaysShowLastPageLink
                                totalPages={pageNumMax}
                            />
                        </ColumnLayout.Column>
                        <ColumnLayout.Column span={6}>
                            <div style={{ width: '100%', display: 'flex' }}>
                                <span style={{ paddingRight: '8px' }}>
                                    <Select value={itemsPerPage} onChange={(ev, { value }) => {setItemsPerPage(value); setPageNum(1);}} inline>
                                        <Select.Option label="10 alerts per page" value="10" />
                                        <Select.Option label="20 alerts per page" value="20" />
                                        <Select.Option label="50 alerts per page" value="50" />
                                        <Select.Option label="100 alerts per page" value="100" />
                                    </Select>
                                </span>
                                <span style={{ paddingRight: '4px' }}>
                                    Table display filter:
                                </span>
                                <span style={{ paddingRight: '8px' }}>
                                    <Text canClear value={displaySearchFilter} onChange={onDisplaySearchFilterChange} inline />
                                </span>
                            </div>
                        </ColumnLayout.Column>
                    </ColumnLayout.Row>
                    <ColumnLayout.Row>
                        <ColumnLayout.Column span={12}>
                            <Table stripeRows rowExpansion="controlled">
                                <Table.Head>
                                    <Table.HeadCell onSort={handleSort} sortKey="_time" sortDir={"_time" === sortKey ? sortDir : 'none'}>Time</Table.HeadCell>
                                    <Table.HeadCell onSort={handleSort} sortKey="type" sortDir={"type" === sortKey ? sortDir : 'none'}>Type</Table.HeadCell>
                                    <Table.HeadCell onSort={handleSort} sortKey="severity" sortDir={"severity" === sortKey ? sortDir : 'none'}>Severity</Table.HeadCell>
                                    <Table.HeadCell onSort={handleSort} sortKey="entity" sortDir={"entity" === sortKey ? sortDir : 'none'}>Entity</Table.HeadCell>
                                    <Table.HeadCell onSort={handleSort} sortKey="status" sortDir={"status" === sortKey ? sortDir : 'none'}>Status</Table.HeadCell>
                                    <Table.HeadCell onSort={handleSort} sortKey="analyst" sortDir={"analyst" === sortKey ? sortDir : 'none'}>Analyst</Table.HeadCell>
                                    <Table.HeadCell>Data</Table.HeadCell>
                                </Table.Head>
                                <Table.Body>
                                    {visibleTableData.map((row, idx) => (
                                        <Table.Row key={row.kv_key} onExpansion={(e) => handleOnExpansion(row)} expanded={row.kv_key in expandedInfo && expandedInfo[row.kv_key].expanded}
                                        expansionRow={getExpansionRow(row, idx % 2 == 1)}>
                                            <Table.Cell>{row._time}</Table.Cell>
                                            <Table.Cell>{row.type}</Table.Cell>
                                            <Table.Cell><Severity level={row.severity}>{row.severity}</Severity></Table.Cell>
                                            <Table.Cell><span style={{ maxWidth: '200px', overflow: 'hidden', display: 'block', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.entity}</span></Table.Cell>
                                            <Table.Cell>{row.status}</Table.Cell>
                                            <Table.Cell>{row.analyst}</Table.Cell>
                                            <Table.Cell>{JSON.stringify(JSON.parse(row.data).data, null, ' ')}</Table.Cell>
                                        </Table.Row>
                                    ))}
                                </Table.Body>
                            </Table>
                            {visibleTableData.length === 0 ? (
                                <aside>
                                    No data based on current filters.
                                </aside>
                            )
                                : null
                            }
                        </ColumnLayout.Column>
                    </ColumnLayout.Row>
                </ColumnLayout>
            </div>
        );
    }
};

S3Table.propTypes = {
    userTheme: PropTypes.string.isRequired
};

export default S3Table;
