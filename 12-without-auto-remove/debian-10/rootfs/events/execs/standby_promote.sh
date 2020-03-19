#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail
# set -o xtrace # Uncomment this line for debugging purpose
# shellcheck disable=SC1090
# shellcheck disable=SC1091

. "$REPMGR_EVENTS_DIR/execs/includes/anotate_event_processing.sh"
. "$REPMGR_EVENTS_DIR/execs/includes/lock_primary.sh"
. "$REPMGR_EVENTS_DIR/execs/includes/unlock_standby.sh"

rm -f "${POSTGRESQL_DATA_DIR}/${STANDBY_ALREADY_CLONED_FILENAME}"
date --rfc-3339=ns > "${POSTGRESQL_DATA_DIR}/${BECOME_MASTER_FILENAME}"
