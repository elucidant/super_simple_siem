# The format and semantics of this file are described in this article at Python.org:
#
# [Configuration file format](https://docs.python.org/2/library/logging.config.html#configuration-file-format)
#
# This file must contain sections called [loggers], [handlers] and
# [formatters] which identify by name the entities of each type which are defined in the
# file. For each such entity, there is a separate section which identifies how that entity
# is configured.

keys = <a list of available keys separated by comma>
* appears in [loggers], [handlers] or [formatters]
* describes the available [logger_<name>], [handler_<name>] or [formatter_<name>]

level = <DEBUG|INFO|WARNING|ERROR|CRITICAL|NOTSET>
*  For the root logger only, NOTSET means that all messages will be logged.

handlers = <comma-separated list>
*  A comma-separated list of handler names, which must appear in the
   [handlers] section.
*  These names must appear in the [handlers] section and have corresponding
   sections in the configuration file.

qualname = <string>
*  The hierarchical channel name of the logger (the name used by the
   application to get the logger).

propagate = <0|1>
*  Set to "1" to indicate that messages must propagate to handlers higher
   up the logger hierarchy from this logger.
*  Set to "0" to indicate that messages are not propagated to handlers
   up the hierarchy.

class = <string>
*  Indicates the handler's class, as determined by eval() in the logging package's namespace.

args = <comma-separated list>
*  The list of arguments to the constructor for the handler class, when
   eval()uated in the context of the logging package's namespace.

formatter = <string>
*  The key name of the formatter for this handler.
*  If blank, a default formatter (logging._defaultFormatter) is used.
*  If a name is specified, it must appear in the [formatters] section and
   have a corresponding section in the configuration file.

format = <logger format pattern>
* for pattern format see: https://docs.python.org/2/library/logging.config.html#user-defined-objects
