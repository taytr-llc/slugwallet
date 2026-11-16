#!/bin/bash

# This script performs different checks on the sample-slugwallet.conf file:
# 1. Checks that all relevant options of slugwallet are included.
# 2. Verifies that defaults are labeled if there are also further examples.
# 3. Checks that all default values of slugwallet are mentioned correctly,
#    including empty defaults and booleans which are set to false by default.

set -e

CONF_FILE=${1:-sample-slugwallet.conf}

# Get the directory containing this script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
SAMPLE_CONF="$REPO_DIR/$CONF_FILE"

# Check if sample config file exists.
if [ ! -f "$SAMPLE_CONF" ]; then
    echo "ERROR: $CONF_FILE not found at $SAMPLE_CONF"
    exit 1
fi

SLUGWALLET_BIN="slugwallet"

# Check if slugwallet binary exists and is executable.
if [ ! -x "$(which "$SLUGWALLET_BIN" 2>/dev/null)" ]; then
    echo "ERROR: $SLUGWALLET_BIN binary not found in PATH or not executable"
    exit 1
fi

# Get slugwallet help output.
FILE_TMP=$(mktemp)
"$SLUGWALLET_BIN" --help > "$FILE_TMP" 2>&1 || true
SLUGWALLET_HELP="$(cat $FILE_TMP) --end"

# SLUGWALLET_OPTIONS is a list of all options of slugwallet including the equal
# sign, which is needed to distinguish between booleans and other variables. It
# is created by reading the first two columns of slugwallet --help.
SLUGWALLET_OPTIONS="$(cat $FILE_TMP | \
    awk '{
        option="";
        if ($1 ~ /^--/){option=$1};
        if ($2 ~ /^--/){option=$2};
        if (match(option,  /--[^=]+[=]*/))
            {printf "%s ", substr(option, RSTART, RLENGTH)}
        }
        END { printf "%s", "--end"}')"
rm $FILE_TMP

# OPTIONS_NO_CONF is a list of all options without any expected entries in
# sample-slugwallet.conf. There's no validation needed for these options.
OPTIONS_NO_CONF="help version configfile end"

# OPTIONS_NO_SLUGWALLET_DEFAULT_VALUE_CHECK is a list of options with default
# values set, but there aren't any returned defaults by slugwallet --help.
# Defaults have to be included in sample-slugwallet.conf but no further checks
# are performed.
# The sample documents Unix-style application paths; defaults vary by OS.
OPTIONS_NO_SLUGWALLET_DEFAULT_VALUE_CHECK="rpclisten legacyrpclisten experimentalrpclisten profile rpcconnect cafile proxy appdata rpccert rpckey logdir"

# EXITCODE is returned at the end after all checks are performed and set to 1 if
# a validation error occurs. COUNTER counts the checked options.
EXITCODE=0
COUNTER=0

echo "Checking $CONF_FILE..."

for OPTION in $SLUGWALLET_OPTIONS; do
    # Determination of the clean name of the option without leading -- and
    # possible = at the end.
    OPTION_NAME=${OPTION##--}
    OPTION_NAME=${OPTION_NAME%=}

    # Skip if there is no expected entry in sample-slugwallet.conf.
    echo "$OPTIONS_NO_CONF" | grep -qw $OPTION_NAME && continue
    COUNTER=$((COUNTER+1))

    # Determine the default value of slugwallet. If the option has no equal sign,
    # it is boolean and set to false.
    # For other options we grep the text between the current option and the next
    # option from SLUGWALLET_HELP. The default value is given in brackets
    # (default: xx) In the case of durations expressed in hours or minutes, the
    # indications of '0m0s' and '0s' are removed, as they provide redundant
    # information. HOME is replaced with general values.
    if [[ "$OPTION" == *"="* ]]; then
        OPTION_NEXT="$(echo "$SLUGWALLET_OPTIONS" | sed -E -e "s/.*$OPTION //" \
            -e "s/([^ ]*).*/\1/")"
        DEFAULT_VALUE_SLUGWALLET="$(echo $SLUGWALLET_HELP | \
            sed -E -e "s/.*--${OPTION##--}//" \
            -e "s/--${OPTION_NEXT##--}.*//" \
            -e '/(default:.*)/ {' \
                -e 's/.*\(default: ([^)]*)\).*/\1/' -e 't end' -e '}' \
            -e 's/.*//' -e ':end' \
            -e "s#m0s#m#g" \
            -e "s#h0m#h#g" \
            -e "s#$HOME#~#g")"
    else
        DEFAULT_VALUE_SLUGWALLET="false"
    fi

    # An option is considered included in the sample-slugwallet.conf if there is
    # a match of the following regex.
    OPTION_REGEX="^;[ ]*$OPTION_NAME=[^ ]*$"

    # Perform the different checks now. If one fails we move to the next option.
    # 1. check if the option is included in the sample-slugwallet.conf.
    if [ $(grep -c "$OPTION_REGEX" $SAMPLE_CONF) -eq 0 ]; then
        echo "Option $OPTION_NAME: no default or example included in $CONF_FILE"
        EXITCODE=1
        continue
    fi
    
    # Skip if no default value check should be performed.
    echo "$OPTIONS_NO_SLUGWALLET_DEFAULT_VALUE_CHECK" | grep -wq $OPTION_NAME && continue

    # 2. Check that the default value is labeled if it is included multiple
    # times.
    if [ $(grep -c "$OPTION_REGEX" $SAMPLE_CONF) -ge 2 ]; then
        # For one option there has to be a preceding line "; Default:"
        # If it matches we grep the default value from the file.
        if grep -A 1 "^; Default:" $SAMPLE_CONF | grep -q "$OPTION_REGEX"; then
            DEFAULT_VALUE_CONF="$(grep -A 1 "^; Default:" $SAMPLE_CONF | \
               grep "$OPTION_REGEX" | cut -d= -f2)"

        else
            echo "Option $OPTION_NAME: mentioned multiple times in $CONF_FILE but without a default value"
            EXITCODE=1
            continue
        fi
    else
        # If there is only one entry in sample-slugwallet.conf we grep the
        # default value.
        DEFAULT_VALUE_CONF=$(grep "$OPTION_REGEX" $SAMPLE_CONF | cut -d= -f2)
    fi
    
    # 3. Compare the default value of slugwallet --help with the value in the
    # sample-slugwallet.conf file. If slugwallet doesn't provide a default value,
    # it is allowed for the value in the file to be '0' or '0s'. For boolean
    # options, allow both 'false' and '0' representations.
    if [ ! "$DEFAULT_VALUE_SLUGWALLET" == "$DEFAULT_VALUE_CONF" ]; then

        if [ -z "$DEFAULT_VALUE_SLUGWALLET" ] && [ "$DEFAULT_VALUE_CONF" == "0" ]; then
            true

        elif [ -z "$DEFAULT_VALUE_SLUGWALLET" ] && [ "$DEFAULT_VALUE_CONF" == "0s" ]; then
            true

        elif [ "$DEFAULT_VALUE_SLUGWALLET" == "false" ] && [ "$DEFAULT_VALUE_CONF" == "0" ]; then
            true

        else
            echo "Option $OPTION_NAME: defaults don't match - $CONF_FILE: '$DEFAULT_VALUE_CONF', slugwallet: '$DEFAULT_VALUE_SLUGWALLET'"
            EXITCODE=1
            continue
        fi
    fi

done

echo "$COUNTER options were checked"

if [ $EXITCODE -eq 0 ]; then
    echo "SUCCESS: All slugwallet configuration options are present and correctly configured in $CONF_FILE"
    echo "$CONF_FILE validation completed successfully!"
else
    echo "ERROR: Configuration validation failed"
fi

exit $EXITCODE