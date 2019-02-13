[phishing://default]
*This is how the phishing input is configured

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

lag_seconds = <integer>
*How many seconds to wait from the time the message was reported before the message is considered for processing, defaults to 3600

move_to_completed = [true|false]
*If true moves the message to the 'Completed' folder which must exist, defaults to false.

