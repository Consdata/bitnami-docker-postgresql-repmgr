#!/bin/bash

. /opt/bitnami/scripts/liblog.sh
. /opt/bitnami/scripts/libos.sh

########################
# Get repmgr node status
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_get_replication_lag() {
    info "Getting replication lag..."
    local -r flags=("node" "check" "-f" "$REPMGR_CONF_FILE" "-qt" "--replication-lag")

    debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
}

########################
# Waits until the lag will be resolve
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_wait_for_resolve_replication_lag() {
    local return_value=1
    local -i timeout=$POSTGRESQL_REPLICATION_LAG_MAX_TIMEOUT
    local -i step=10
    local -i max_tries=$(( timeout / step ))
    local lag
    info "Waiting for resolve lag..."
    for ((i=0,current_try=1 ; i <= timeout ; i+=step,current_try++ )); do
        lag="$(repmgr_get_replication_lag)"
        local exit_code=$?
        if [[ $exit_code -ne 0 && $exit_code -ne 1 ]]; then
            debug "[$current_try/$max_tries] Cannot get replication lag for this node (node return: $lag)"
        else
            if [[ "$lag" != "OK"* ]]; then
                debug "[$current_try/$max_tries] Found lag on this node (node return: $lag)"
            else
                debug "[$current_try/$max_tries] Lag is OK (node return: $lag)"
                return_value=0 && break
            fi
        fi
        sleep "$step"
    done
    return $return_value
}

########################
# Check if that node should follow primary
# Arguments:
#   None
# Returns:
#   Boolean
#########################
should_follow_primary() {
    info "should_follow_primary: Checking node(role: $REPMGR_ROLE) replication slots..."

    local -r query="SELECT count(*) from pg_replication_slots s LEFT JOIN nodes n ON s.slot_name=n.slot_name WHERE n.node_id=$(repmgr_get_node_id);"
    if ! count_replication_slots="$(echo "$query" | NO_ERRORS=true postgresql_remote_execute "$REPMGR_CURRENT_PRIMARY_HOST" "$REPMGR_CURRENT_PRIMARY_PORT" "$REPMGR_DATABASE" "$REPMGR_USERNAME" "$REPMGR_PASSWORD" "-tA")"; then
        warn "Failed to check replication slot from the node '$REPMGR_CURRENT_PRIMARY_HOST:$REPMGR_CURRENT_PRIMARY_PORT'!"
        exit 5
    elif [[ -z "$count_replication_slots" ]]; then
        warn "Failed to get information about replication slot!"
        exit 6
    else
      debug "Replication slots found for this node: $count_replication_slots"

      local -r query_rep_slots="SELECT * from pg_replication_slots s LEFT JOIN nodes n ON s.slot_name=n.slot_name WHERE n.node_id=$(repmgr_get_node_id);"
      local -r rep_slots="$(echo "$query_rep_slots" | NO_ERRORS=true postgresql_remote_execute "$REPMGR_CURRENT_PRIMARY_HOST" "$REPMGR_CURRENT_PRIMARY_PORT" "$REPMGR_DATABASE" "$REPMGR_USERNAME" "$REPMGR_PASSWORD" "-tA")"
      debug "Replication slots: $rep_slots"

      if [[ "$count_replication_slots" -gt 0 || "$REPMGR_ROLE" = "primary" ]]; then
        debug "should_follow_primary: returns no"
        echo 'no'
      else
        debug "should_follow_primary: returns yes"
        echo 'yes'
      fi
    fi
}

########################
# Follow a primary node
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_follow_primary() {
    info "Following primary node..."
    local -r flags=("standby" "follow" "-f" "$REPMGR_CONF_FILE" "--force" "--verbose")

    if [[ "$REPMGR_USE_PASSFILE" = "true" ]]; then
        PGPASSFILE="$REPMGR_PASSFILE_PATH" debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
    else
        PGPASSWORD="$REPMGR_PASSWORD" debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
    fi
}
