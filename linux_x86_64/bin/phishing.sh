#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source $DIR/../miniconda2/bin/activate phishing
unset LD_LIBRARY_PATH
unset PYTHONPATH
date >> /tmp/super_simple_siem_phishing.log
python $DIR/../../bin/phishing.lib conda "$@"
