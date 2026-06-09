python.version = {default|python|python2|python3|python3.7|python3.9|latest}
* DEPRECATED. Use 'python.required' instead to specify which Python versions the
  script supports.
* For Python scripts only, specifies which Python version to use.
* A value of either "default" or "python" means to use the system-wide 
  default Python version.
* Set to "python3" or "python3.9" to use the Python 3.9 version.
* A value of "python3.7" could result in splunkd logging a warning, 
  depending on how you configured log levels or the 'python.version'
  setting in the server.conf configuration file. Regardless, the
  system uses Python 3.9.
* In the context of configuring apps, the "latest" value is not currently
  supported. It is related to a feature that is still under development.
* Optional.
* Default: Not set; uses the system-wide Python version.

python.required = <comma-separated list>
* For Python scripts only, the versions of Python that the script supports.
* This setting takes precedence over the 'python.version' setting if both
  have values.
* The Splunk platform selects the highest version of Python that is
  available from the list that you provide.
* The following values are supported:
  * "3.9": The script supports Python version 3.9.
  * "3.13": The script supports Python version 3.13.
  * "latest": The script uses the latest Python interpreter available.
    * Where possible, use a specific version string rather than "latest".
    * NOTE: The "latest" value is an internal value that is related to
      a feature that is still under development.
* NOTE: Use this setting instead of the deprecated 'python.version' setting.
* This setting is optional.
* Default: Not set; uses 'python.version' if that setting has a value.

