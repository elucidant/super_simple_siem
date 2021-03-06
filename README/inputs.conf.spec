[phishing://default]
*This is how the phishing input is configured

server = <value>
*Server name, leave empty for autodiscover, use outlook.office365.com for O365

mailbox = <value>
*mailbox to monitor (e.g. phishing@example.com)

domain = <value>
*Domain name

username = <value>
*Username to used to access mailbox

password = <value>
*Password for username

folder = <value>
*Folder name to monitor (fallbacks to Inbox if missing)

max_count = <integer>
*Maximum number of emails to retrieve per invocation, defaults to 100

alert_lag_seconds = <integer>
*How many seconds to wait from the time the message was reported before the message is considered for alert processing, defaults to 600

metrics_lag_seconds = <integer>
*How many seconds to wait from the time the message was reported before the message is considered for metrics processing, defaults to 3600

move_to_completed = [true|false]
*If true moves the message to the 'Completed' folder which must exist, defaults to false.



[trap://default]
*This is how the phishing input is configured

mailbox = <value>
*mailbox to monitor (e.g. proofpointdetection.serviceaccount@example.com)

server = <value>
*Server name, leave empty for autodiscover, use outlook.office365.com for O365

username = <value>
*Username to used to access mailbox, prefix with domain

password = <value>
*Password for username

folder = <value>
*Folder name to monitor (fallbacks to Inbox if missing)

max_count = <integer>
*Maximum number of emails to retrieve per invocation, defaults to 100

lag_seconds = <integer>
*How many seconds to wait from the time the message was reported before the message is considered for processing, defaults to 3600

