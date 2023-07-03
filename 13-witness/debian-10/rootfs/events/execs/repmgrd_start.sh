#!/bin/bash

. /opt/bitnami/scripts/liblog.sh

set -o errexit
set -o nounset
set -o pipefail
# set -o xtrace # Uncomment this line for debugging purpose
# shellcheck disable=SC1090
# shellcheck disable=SC1091

# Set the environment variables for the node's role
eval "$(repmgr_set_role)"

debug "repmgrd_start.sh: init"
if [[ "$REPMGR_ROLE" = "standby" ]]; then
  if ! should_follow=$(should_follow_primary); then
    exit 7
  elif is_boolean_yes "$should_follow"; then
    repmgr_follow_primary
  else
    debug "repmgrd_start.sh: standby already following primary"
  fi
fi
