#!/bin/bash
#
# Bitnami Postgresql Repmgr library

# shellcheck disable=SC1091

# Load Generic Libraries
. /opt/bitnami/scripts/libfile.sh
. /opt/bitnami/scripts/libfs.sh
. /opt/bitnami/scripts/liblog.sh
. /opt/bitnami/scripts/libos.sh
. /opt/bitnami/scripts/libvalidations.sh
. /opt/bitnami/scripts/libnet.sh

########################
# Get repmgr node id
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   String
#########################
repmgr_get_node_id() {
    local num
    if [[ "$REPMGR_NODE_ID" != "" ]]; then
        echo "$REPMGR_NODE_ID"
    else
        num="${REPMGR_NODE_NAME##*-}"
        if [[ "$num" != "" ]]; then
            num=$((num+1000))
            echo "$num"
        fi
    fi
}

########################
# Get repmgr password method
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   String
#########################
repmgr_get_env_password() {
    if [[ "$REPMGR_USE_PASSFILE" = "true" ]]; then
        echo "PGPASSFILE=${REPMGR_PASSFILE_PATH}"
    else
        echo "PGPASSWORD=${REPMGR_PASSWORD}"
    fi
}

########################
# Get repmgr conninfo password method
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   String
#########################
repmgr_get_conninfo_password() {
    if [[ "$REPMGR_USE_PASSFILE" = "true" ]]; then
        echo "passfile=${REPMGR_PASSFILE_PATH}"
    else
        echo "password=${REPMGR_PASSWORD}"
    fi
}

########################
# Validate settings in REPMGR_* env. variables
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_validate() {
    info "Validating settings in REPMGR_* env vars..."
    local error_code=0

    # Auxiliary functions
    print_validation_error() {
        error "$1"
        error_code=1
    }

    if [[ -z "$REPMGR_WITNESS_NODE" && "$REPMGR_NODE_TYPE" != "witness" ]]; then
        print_validation_error "The witness cannot be empty. Set the environment variable REPMGR_WITNESS_NODE with a witness node host (You can also change default port (5432) changing REPMGR_WITNESS_PORT)."
    fi
    if [[ -z "$REPMGR_PRIMARY_HOST" ]]; then
        print_validation_error "The initial primary host is required. Set the environment variable REPMGR_PRIMARY_HOST with the initial primary host."
    fi
    if [[ -z "$REPMGR_NODE_NAME" ]]; then
        print_validation_error "The node name is required. Set the environment variable REPMGR_NODE_NAME with the node name."
    elif [[ ! "$REPMGR_NODE_NAME" =~ ^.*+-[0-9]+$ ]]; then
        print_validation_error "The node name does not follow the required format. Valid format: ^.*+-[0-9]+$"
    fi
    if [[ -z "$(repmgr_get_node_id)" ]]; then
        print_validation_error "The node id is required. Set the environment variable REPMGR_NODE_ID with the node id."
    fi
    if [[ -z "$REPMGR_NODE_NETWORK_NAME" ]]; then
        print_validation_error "The node network name is required. Set the environment variable REPMGR_NODE_NETWORK_NAME with the node network name."
    fi
    # Credentials validations
    if [[ -z "$REPMGR_USERNAME" ]] || [[ -z "$REPMGR_PASSWORD" ]]; then
        print_validation_error "The repmgr credentials are mandatory. Set the environment variables REPMGR_USERNAME and REPMGR_PASSWORD with the repmgr credentials."
    fi

    if [[ "$REPMGR_USE_PASSFILE" = "true" ]]; then
        local -r psql_major_version="$(postgresql_get_major_version)"
        if [[ "$psql_major_version" -le "9" ]]; then
            warn "Variable REPMGR_USE_PASSFILE is not compatible with PostgreSQL ${psql_major_version}. It will be disabled."
            export REPMGR_USE_PASSFILE="false"
        fi
    fi

    if ! is_yes_no_value "$REPMGR_PGHBA_TRUST_ALL"; then
        print_validation_error "The allowed values for REPMGR_PGHBA_TRUST_ALL are: yes or no."
    fi
    if ! is_yes_no_value "$REPMGR_UPGRADE_EXTENSION"; then
        print_validation_error "The allowed values for REPMGR_UPGRADE_EXTENSION are: yes or no."
    fi

    [[ "$error_code" -eq 0 ]] || exit "$error_code"
}

########################
# Ask partner nodes which node is the primary
# Globals:
#   REPMGR_*
# Arguments:
#   Non
# Returns:
#   String[] - (host port)
#########################
repmgr_get_upstream_node() {
    local primary_conninfo
    local pretending_primary_host=""
    local pretending_primary_port=""
    local host=""
    local port=""
    local suggested_primary_host=""
    local suggested_primary_port=""

    if [[ -n "$REPMGR_WITNESS_NODE" ]]; then
        info "Searching primary node using witness..."
        host="$REPMGR_WITNESS_NODE"
        port="${REPMGR_WITNESS_PORT:-5432}"
        debug "Checking witness '$host:$port'..."
        local query="SELECT conninfo FROM repmgr.show_nodes WHERE (upstream_node_name IS NULL OR upstream_node_name = '') AND active=true"
        if ! primary_conninfo="$(echo "$query" | NO_ERRORS=true postgresql_remote_execute "$host" "$port" "$REPMGR_DATABASE" "$REPMGR_USERNAME" "$REPMGR_PASSWORD" "-tA")"; then
            debug "Skipping: failed to get primary from the node '$host:$port'!"
        elif [[ -z "$primary_conninfo" ]]; then
            debug "Skipping: failed to get information about primary nodes!"
        elif [[ "$(echo "$primary_conninfo" | wc -l)" -eq 1 ]]; then
            suggested_primary_host="$(echo "$primary_conninfo" | awk -F 'host=' '{print $2}' | awk '{print $1}')"
            suggested_primary_port="$(echo "$primary_conninfo" | awk -F 'port=' '{print $2}' | awk '{print $1}')"
            debug "Pretending primary role node - '${suggested_primary_host}:${suggested_primary_port}'"
            if [[ -n "$pretending_primary_host" ]]; then
                if [[ "${pretending_primary_host}:${pretending_primary_port}" != "${suggested_primary_host}:${suggested_primary_port}" ]]; then
                    warn "Conflict of pretending primary role nodes (previously: '${pretending_primary_host}:${pretending_primary_port}', now: '${suggested_primary_host}:${suggested_primary_port}')"
                    pretending_primary_host="" && pretending_primary_port=""
                fi
            else
                debug "Pretending primary set to '${suggested_primary_host}:${suggested_primary_port}'!"
                pretending_primary_host="$suggested_primary_host"
                pretending_primary_port="$suggested_primary_port"
            fi
        else
            warn "There were more than one primary when getting primary from node '$host:$port'"
            pretending_primary_host="" && pretending_primary_port=""
        fi
    fi

    echo "$pretending_primary_host"
    echo "$pretending_primary_port"
}

########################
# Check node is the same like $REPMGR_PRIMARY_HOST $REPMGR_PRIMARY_PORT
# Arguments:
#   None
# Returns:
#   Boolean
#########################
node_is_the_same_like_repmgr_primary_variable() {
    if [[ "${REPMGR_PRIMARY_HOST}:${REPMGR_PRIMARY_PORT}" = "${REPMGR_NODE_NETWORK_NAME}:${REPMGR_PORT_NUMBER}" ]]; then
      true
    else
      false
    fi
}

########################
# Gets the node that is currently set as primary node
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   String[] - (host port)
#########################
repmgr_get_primary_node() {
    local upstream_node
    local upstream_host
    local upstream_port
    local primary_host=""
    local primary_port="$REPMGR_PRIMARY_PORT"

    readarray -t upstream_node < <(repmgr_get_upstream_node)
    upstream_host=${upstream_node[0]}
    upstream_port=${upstream_node[1]:-$REPMGR_PRIMARY_PORT}
    [[ -n "$upstream_host" ]] && info "Auto-detected primary node: '${upstream_host}:${upstream_port}'"

    if [[ -f "$REPMGR_PRIMARY_ROLE_LOCK_FILE_NAME" ]]; then
        info "This node was acting as a primary before restart!"

        if [[ -z "$upstream_host" ]] || [[ "${upstream_host}:${upstream_port}" = "${REPMGR_NODE_NETWORK_NAME}:${REPMGR_PORT_NUMBER}" ]]; then
            info "Can not find new primary. Starting PostgreSQL normally..."
        else
            info "Current master is '${upstream_host}:${upstream_port}'. Cloning/rewinding it and acting as a standby node..."
            rm -f "$REPMGR_PRIMARY_ROLE_LOCK_FILE_NAME"
            export REPMGR_SWITCH_ROLE="yes"
            primary_host="$upstream_host"
            primary_port="$upstream_port"
        fi
    else
        if [[ -z "$upstream_host" ]]; then
            if ! node_is_the_same_like_repmgr_primary_variable; then
              primary_host="$REPMGR_PRIMARY_HOST"
              primary_port="$REPMGR_PRIMARY_PORT"
            fi
        else
            primary_host="$upstream_host"
            primary_port="$upstream_port"
        fi
    fi

    [[ -n "$primary_host" ]] && debug "Primary node: '${primary_host}:${primary_port}'"
    echo "$primary_host"
    echo "$primary_port"
}

########################
# Generates env vars for the node
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   Series of exports to be used as 'eval' arguments
#########################
repmgr_set_role() {
    local role="standby"
    local primary_host=""
    local primary_port=""

    if [[ "$REPMGR_NODE_TYPE" != "witness" ]]; then
        local primary_node
        readarray -t primary_node < <(repmgr_get_primary_node)
        primary_host=${primary_node[0]}
        primary_port=${primary_node[1]:-$REPMGR_PRIMARY_PORT}
    fi

    if [[ -z "$primary_host" ]]; then
        info "There are no nodes with primary role. Assuming the primary role ($REPMGR_PRIMARY_HOST:$REPMGR_PRIMARY_PORT)..."
        primary_host="${REPMGR_PRIMARY_HOST}"
        primary_port="${REPMGR_PRIMARY_PORT}"
    fi

    if [[ "$REPMGR_NODE_TYPE" != "witness" && "$primary_host" = "$REPMGR_NODE_NETWORK_NAME" && "$primary_port" = "$REPMGR_PORT_NUMBER" ]]; then
        role="primary"
    fi

    cat <<EOF
export REPMGR_ROLE="$role"
export REPMGR_CURRENT_PRIMARY_HOST="$primary_host"
export REPMGR_CURRENT_PRIMARY_PORT="$primary_port"
EOF
}

########################
# Change a Repmgr configuration file by setting a property
# Globals:
#   REPMGR_*
# Arguments:
#   $1 - property
#   $2 - value
#   $3 - Path to configuration file (default: $REPMGR_CONF_FILE)
# Returns:
#   None
#########################
repmgr_set_property() {
    local -r property="${1:?missing property}"
    local -r value="${2:-}"
    local -r conf_file="${3:-$REPMGR_CONF_FILE}"

    replace_in_file "$conf_file" "^#*\s*${property}\s*=.*" "${property} = '${value}'" false
}


########################
# Create the repmgr user (with )
# Globals:
#   REPMGR_*
#   POSTGRESQL_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_create_repmgr_user() {
    local postgres_password="$POSTGRESQL_PASSWORD"
    local -r escaped_password="${REPMGR_PASSWORD//\'/\'\'}"
    info "Creating repmgr user: $REPMGR_USERNAME"

    [[ "$POSTGRESQL_USERNAME" != "postgres" ]] && [[ -n "$POSTGRESQL_POSTGRES_PASSWORD" ]] && postgres_password="$POSTGRESQL_POSTGRES_PASSWORD"
    # The repmgr user is created as superuser for simplicity (ref: https://repmgr.org/docs/4.3/quickstart-repmgr-user-database.html)
    echo "CREATE ROLE \"${REPMGR_USERNAME}\" WITH LOGIN CREATEDB PASSWORD '${escaped_password}';" | postgresql_execute "" "postgres" "$postgres_password"
    echo "ALTER USER ${REPMGR_USERNAME} WITH SUPERUSER;" | postgresql_execute "" "postgres" "$postgres_password"
    # set the repmgr user's search path to include the 'repmgr' schema name (ref: https://repmgr.org/docs/4.3/quickstart-repmgr-user-database.html)
    echo "ALTER USER ${REPMGR_USERNAME} SET search_path TO repmgr, \"\$user\", public;" | postgresql_execute "" "postgres" "$postgres_password"
}

########################
# Creates the repmgr database
# Globals:
#   REPMGR_*
#   POSTGRESQL_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_create_repmgr_db() {
    local postgres_password="$POSTGRESQL_PASSWORD"
    info "Creating repmgr database: $REPMGR_DATABASE"

    [[ "$POSTGRESQL_USERNAME" != "postgres" ]] && [[ -n "$POSTGRESQL_POSTGRES_PASSWORD" ]] && postgres_password="$POSTGRESQL_POSTGRES_PASSWORD"
    echo "CREATE DATABASE $REPMGR_DATABASE;" | postgresql_execute "" "postgres" "$postgres_password"
}

########################
# Use a different PostgreSQL configuration file by pretending it's an injected custom configuration
# Globals:
#   POSTGRESQL_MOUNTED_CONF_DIR
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_inject_postgresql_configuration() {
    debug "Injecting a new postgresql.conf file..."
    postgresql_create_config
    # ref: https://repmgr.org/docs/4.3/quickstart-postgresql-configuration.html
    if [[ -n "$POSTGRESQL_SHARED_PRELOAD_LIBRARIES" ]]; then
        if [[ "$POSTGRESQL_SHARED_PRELOAD_LIBRARIES" =~ ^(repmgr|REPMGR)$ ]]; then
            postgresql_set_property "shared_preload_libraries" "$POSTGRESQL_SHARED_PRELOAD_LIBRARIES"
        else
            postgresql_set_property "shared_preload_libraries" "repmgr, ${POSTGRESQL_SHARED_PRELOAD_LIBRARIES}"
        fi
    else
        postgresql_set_property "shared_preload_libraries" "repmgr"
    fi
    postgresql_set_property "max_wal_senders" "16"
    postgresql_set_property "max_replication_slots" "10"
    postgresql_set_property "wal_level" "$POSTGRESQL_WAL_LEVEL"
    postgresql_set_property "archive_mode" "on"
    postgresql_set_property "hot_standby" "on"
    postgresql_set_property "archive_command" "/bin/true"
    postgresql_configure_connections
    postgresql_configure_timezone
    # Redirect logs to POSTGRESQL_LOG_FILE
    postgresql_configure_logging
    postgresql_set_property "logging_collector" "on"
    postgresql_set_property "log_directory" "$POSTGRESQL_LOG_DIR"
    postgresql_set_property "log_filename" "postgresql.log"
    is_boolean_yes "$POSTGRESQL_ENABLE_TLS" && postgresql_configure_tls
    is_boolean_yes "$POSTGRESQL_ENABLE_TLS" && [[ -n $POSTGRESQL_TLS_CA_FILE ]] && postgresql_tls_auth_configuration
    cp "$POSTGRESQL_CONF_FILE" "${POSTGRESQL_MOUNTED_CONF_DIR}/postgresql.conf"
}

########################
# Use a different pg_hba.conf file by pretending it's an injected custom configuration\
# Globals:
#   POSTGRESQL_MOUNTED_CONF_DIR
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_inject_pghba_configuration() {
    debug "Injecting a new pg_hba.conf file..."
    local tls_auth="#"
    if is_boolean_yes "$POSTGRESQL_ENABLE_TLS" && [[ -n $POSTGRESQL_TLS_CA_FILE ]]; then
        tls_auth=""
    fi

    cat > "${POSTGRESQL_MOUNTED_CONF_DIR}/pg_hba.conf" << EOF
host     all            $REPMGR_USERNAME    0.0.0.0/0    trust
host     $REPMGR_DATABASE         $REPMGR_USERNAME    0.0.0.0/0    trust
host     $REPMGR_DATABASE         $REPMGR_USERNAME    ::/0    trust
host     replication      $REPMGR_USERNAME    0.0.0.0/0    trust
host     replication      $REPMGR_USERNAME    ::/0    trust
${tls_auth}hostssl     all             all             0.0.0.0/0               cert
${tls_auth}hostssl     all             all             ::/0                    cert
host     all              all       0.0.0.0/0    trust
host     all              all       ::/0         trust
local    all              all                    trust
EOF
}

########################
# Prepare PostgreSQL default configuration
# Globals:
#   POSTGRESQL_MOUNTED_CONF_DIR
#   REPMGR_MOUNTED_CONF_DIR
#   REPMGR_PASSFILE_PATH
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_postgresql_configuration() {
    info "Preparing PostgreSQL configuration..."
    # User injected custom configuration
    if [[ -d "$REPMGR_MOUNTED_CONF_DIR" ]] && compgen -G "$REPMGR_MOUNTED_CONF_DIR"/* > /dev/null; then
        debug "User injected custom configuration detected!"
    fi
    ensure_dir_exists "$POSTGRESQL_MOUNTED_CONF_DIR"
    if [[ -f "${REPMGR_MOUNTED_CONF_DIR}/postgresql.conf" ]]; then
        cp "${REPMGR_MOUNTED_CONF_DIR}/postgresql.conf" "${POSTGRESQL_MOUNTED_CONF_DIR}/postgresql.conf"
    else
        repmgr_inject_postgresql_configuration
    fi
    if [[ -f "${REPMGR_MOUNTED_CONF_DIR}/pg_hba.conf" ]]; then
        cp "${REPMGR_MOUNTED_CONF_DIR}/pg_hba.conf" "${POSTGRESQL_MOUNTED_CONF_DIR}/pg_hba.conf"
    else
        repmgr_inject_pghba_configuration
    fi
    if [[ "$REPMGR_USE_PASSFILE" = "true" ]] && [[ ! -f "${REPMGR_PASSFILE_PATH}" ]]; then
        echo "*:*:*:${REPMGR_USERNAME}:${REPMGR_PASSWORD}" > "${REPMGR_PASSFILE_PATH}"
        chmod 600 "${REPMGR_PASSFILE_PATH}"
    fi
}

########################
# Generates repmgr config files
# Globals:
#   REPMGR_*
#   POSTGRESQL_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_generate_repmgr_config() {
    info "Preparing repmgr configuration..."

    cat << EOF >> "${REPMGR_CONF_FILE}.tmp"
event_notification_command='${REPMGR_EVENTS_DIR}/router.sh %n %e %s "%t" "%d"'
ssh_options='-o "StrictHostKeyChecking no" -v'
use_replication_slots='${REPMGR_USE_REPLICATION_SLOTS}'
pg_bindir='${POSTGRESQL_BIN_DIR}'

# FIXME: these 2 parameter should work
node_id=$(repmgr_get_node_id)
node_name='${REPMGR_NODE_NAME}'
location='${REPMGR_NODE_LOCATION}'
conninfo='user=${REPMGR_USERNAME} $(repmgr_get_conninfo_password) host=${REPMGR_NODE_NETWORK_NAME} dbname=${REPMGR_DATABASE} port=${REPMGR_PORT_NUMBER} connect_timeout=${REPMGR_CONNECT_TIMEOUT}'
failover='automatic'
promote_command='$(repmgr_get_env_password) repmgr standby promote -f "${REPMGR_CONF_FILE}" --log-level DEBUG --verbose'
follow_command='$(repmgr_get_env_password) repmgr standby follow -f "${REPMGR_CONF_FILE}" -W --log-level DEBUG --verbose'
reconnect_attempts='${REPMGR_RECONNECT_ATTEMPTS}'
reconnect_interval='${REPMGR_RECONNECT_INTERVAL}'
log_level='${REPMGR_LOG_LEVEL}'
priority='${REPMGR_NODE_PRIORITY}'
degraded_monitoring_timeout='${REPMGR_DEGRADED_MONITORING_TIMEOUT}'
data_directory='${POSTGRESQL_DATA_DIR}'
pg_ctl_options='-l $POSTGRESQL_LOG_FILE -o --config-file="$POSTGRESQL_CONF_FILE --external_pid_file=$POSTGRESQL_PID_FILE --hba_file=$POSTGRESQL_PGHBA_FILE"'
async_query_timeout='${REPMGR_MASTER_RESPONSE_TIMEOUT}'
pg_ctl_options='-o "--config-file=\"${POSTGRESQL_CONF_FILE}\" --external_pid_file=\"${POSTGRESQL_PID_FILE}\" --hba_file=\"${POSTGRESQL_PGHBA_FILE}\""'
EOF

    if [[ -f "${REPMGR_MOUNTED_CONF_DIR}/repmgr.conf" ]]; then
        # remove from default the overrided keys, and append the desired conf
        grep -xvFf "${REPMGR_CONF_FILE}.tmp" "${REPMGR_MOUNTED_CONF_DIR}/repmgr.conf" | awk -F"=" '{print $1;}' > "${REPMGR_CONF_FILE}.keys" && grep -v -f "${REPMGR_CONF_FILE}.keys" "${REPMGR_CONF_FILE}.tmp" > "$REPMGR_CONF_FILE" && cat "${REPMGR_MOUNTED_CONF_DIR}/repmgr.conf" >> "$REPMGR_CONF_FILE"
    else
        cp "${REPMGR_CONF_FILE}.tmp" "${REPMGR_CONF_FILE}"
    fi

    if [[ "$REPMGR_USE_PASSFILE" = "true" ]]; then
        echo "passfile='${REPMGR_PASSFILE_PATH}'" >> "$REPMGR_CONF_FILE"
    fi
}

########################
# Waits until the node responds
# Globals:
#   REPMGR_*
# Arguments:
#   name
#   host
#   port
# Returns:
#   None
#########################
repmgr_wait_node() {
    local -r name="$1"
    local -r host="$2"
    local -r port="$3"
    local return_value=1
    local -i timeout=60
    local -i step=10
    local -i max_tries=$(( timeout / step ))
    local schemata
    info "Waiting for $name node..."
    debug "Wait for schema $REPMGR_DATABASE.repmgr on '${host}:${port}', will try $max_tries times with $step delay seconds (TIMEOUT=$timeout)"
    for ((i = 0 ; i <= timeout ; i+=step )); do
        local query="SELECT 1 FROM information_schema.schemata WHERE catalog_name='$REPMGR_DATABASE' AND schema_name='repmgr'"
        if ! schemata="$(echo "$query" | NO_ERRORS=true postgresql_remote_execute "$host" "$port" "$REPMGR_DATABASE" "$REPMGR_USERNAME" "$REPMGR_PASSWORD" "-tA")"; then
            debug "Host '${host}:${port}' is not accessible"
        else
            if [[ $schemata -ne 1 ]]; then
                debug "Schema $REPMGR_DATABASE.repmgr is still not accessible"
            else
                debug "Schema $REPMGR_DATABASE.repmgr exists!"
                return_value=0 && break
            fi
        fi
        sleep "$step"
    done
    return $return_value
}

########################
# Waits until the primary node responds
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_wait_primary_node() {
    repmgr_wait_node "primary" "$REPMGR_CURRENT_PRIMARY_HOST" "$REPMGR_CURRENT_PRIMARY_PORT"
    return $?
}

########################
# Waits until the witness node responds
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_wait_witness_node() {
    repmgr_wait_node "witness" "$REPMGR_WITNESS_NODE" "$REPMGR_WITNESS_PORT"
    return $?
}

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
    local -i timeout=120
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
# Clones data from primary node
# Globals:
#   REPMGR_*
#   POSTGRESQL_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_clone_primary() {
    info "Cloning data from primary node..."
    local flags=("-f" "$REPMGR_CONF_FILE" "-h" "$REPMGR_CURRENT_PRIMARY_HOST" "-p" "$REPMGR_CURRENT_PRIMARY_PORT" "-U" "$REPMGR_USERNAME" "-d" "$REPMGR_DATABASE" "-D" "$POSTGRESQL_DATA_DIR" "standby" "clone" "--fast-checkpoint")

    if [[ -f "${POSTGRESQL_DATA_DIR}/${FORCE_UNSAFE_CLONE_FILENAME}" ]]; then
      rm "${POSTGRESQL_DATA_DIR}/${FORCE_UNSAFE_CLONE_FILENAME}" || exit $?
      flags+=( "--force" )
      info "USE FORCE FLAG IN CLONE!!!"
    fi

    if [[ "$REPMGR_USE_PASSFILE" = "true" ]]; then
        PGPASSFILE="$REPMGR_PASSFILE_PATH" debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
    else
        PGPASSWORD="$REPMGR_PASSWORD" debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
    fi
    date --rfc-3339=ns > "${POSTGRESQL_DATA_DIR}/${STANDBY_ALREADY_CLONED_FILENAME}"
}

########################
# Rejoin node
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_rewind() {
    if [[ -f "${POSTGRESQL_DATA_DIR}/${FORCE_UNSAFE_CLONE_FILENAME}" ]]; then
      info "Rejoining node..."
      debug "Cloning data from primary node with force flag..."
      repmgr_clone_primary
    fi
}

########################
# Register a node as primary
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_register_primary() {
    info "Registering Primary..."
    local -r flags=("-f" "$REPMGR_CONF_FILE" "master" "register" "--force")

    debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
}

########################
# Unregister standby node
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_unregister_standby() {
    info "Unregistering standby node..."

    local -r flags=("standby" "unregister" "-f" "$REPMGR_CONF_FILE" "--node-id=$(repmgr_get_node_id)")

    # The command below can fail when the node doesn't exist yet
    debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}" || true
}

########################
# Standby follow.
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_standby_follow() {
    info "Running standby follow..."
    local -r flags=("standby" "follow" "-f" "$REPMGR_CONF_FILE" "-W" "--log-level" "DEBUG" "--verbose")

    if [[ "$REPMGR_USE_PASSFILE" = "true" ]]; then
        PGPASSFILE="$REPMGR_PASSFILE_PATH" debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
    else
        PGPASSWORD="$REPMGR_PASSWORD" debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
    fi

}

########################
# Register a node as standby
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_register_standby() {
    info "Registering Standby node..."
    local -r flags=("standby" "register" "-f" "$REPMGR_CONF_FILE" "--force" "--verbose")

    debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
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

########################
# Register a node as witness
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_register_witness() {
    info "Registering Witness node..."
    local -r flags=("witness" "register" "-f" "$REPMGR_CONF_FILE" "--host" "$REPMGR_CURRENT_PRIMARY_HOST" "--port" "$REPMGR_CURRENT_PRIMARY_PORT" "--force" "--verbose")

    if [[ "$REPMGR_USE_PASSFILE" = "true" ]]; then
        PGPASSFILE="$REPMGR_PASSFILE_PATH" debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
    else
        PGPASSWORD="$REPMGR_PASSWORD" debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
    fi
}

########################
# Upgrade repmgr extension
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_upgrade_extension() {
    info "Upgrading repmgr extension..."

    echo "ALTER EXTENSION repmgr UPDATE" | postgresql_execute "$REPMGR_DATABASE" "$REPMGR_USERNAME" "$REPMGR_PASSWORD"
}

########################
# Check if that node should follow primary
# Arguments:
#   None
# Returns:
#   Boolean
#########################
should_follow_primary() {
    info "Checking node(role: $REPMGR_ROLE) replication slots..."

    local -r query="SELECT count(*) from pg_replication_slots s LEFT JOIN nodes n ON s.slot_name=n.slot_name WHERE n.node_id=$(repmgr_get_node_id);"
    if ! count_replication_slots="$(echo "$query" | NO_ERRORS=true postgresql_execute "$REPMGR_DATABASE" "$REPMGR_USERNAME" "$REPMGR_PASSWORD" "$REPMGR_CURRENT_PRIMARY_HOST" "$REPMGR_CURRENT_PRIMARY_PORT" "-tA")"; then
        warn "Failed to check replication slot from the node '$host:$port'!"
        exit 5
    elif [[ -z "$count_replication_slots" ]]; then
        warn "Failed to get information about replication slot!"
        exit 6
    else
      debug "Replication slots found for this node: $count_replication_slots"
      [[ "$count_replication_slots" -gt 0 || "$REPMGR_ROLE" = "primary" ]] && echo 'no' || echo 'yes'
    fi
}

########################
# Initialize repmgr service
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_initialize() {
    if [[ "$REPMGR_NODE_TYPE" != "witness" ]]; then
        if ! node_is_the_same_like_repmgr_primary_variable ||
              ! is_dir_empty "$POSTGRESQL_DATA_DIR" &&
              [[ ! -f "$POSTGRESQL_DATA_DIR/$FORCE_RUN_PRIMARY_WITHOUT_WITNESS_FILENAME" ]]; then
          repmgr_wait_witness_node || exit 1
        fi
        rm -f "$POSTGRESQL_DATA_DIR/$FORCE_RUN_PRIMARY_WITHOUT_WITNESS_FILENAME"
    fi

    # Set the environment variables for the node's role
    eval "$(repmgr_set_role)"

    # Configure postgres
    export POSTGRESQL_MASTER_HOST="$REPMGR_CURRENT_PRIMARY_HOST"
    export POSTGRESQL_MASTER_PORT_NUMBER="$REPMGR_CURRENT_PRIMARY_PORT"
    export POSTGRESQL_REPLICATION_USER="$REPMGR_USERNAME"
    export POSTGRESQL_REPLICATION_PASSWORD="$REPMGR_PASSWORD"

    debug "Node ID: '$(repmgr_get_node_id)', Rol: '$REPMGR_ROLE', Primary Node: '${REPMGR_CURRENT_PRIMARY_HOST}:${REPMGR_CURRENT_PRIMARY_PORT}'"
    info "Initializing Repmgr..."

    ensure_dir_exists "$REPMGR_LOCK_DIR"
    am_i_root && chown "$POSTGRESQL_DAEMON_USER:$POSTGRESQL_DAEMON_GROUP" "$REPMGR_LOCK_DIR"

    if [[ "$REPMGR_ROLE" = "standby" && "$REPMGR_NODE_TYPE" != "witness" ]]; then
        repmgr_wait_primary_node || exit 1
        # TODO: better way to detect it's a 1st boot
        if [[ ! -f "$POSTGRESQL_CONF_FILE" ]] || ! is_boolean_yes "$REPMGR_SWITCH_ROLE"; then
            if [[ ! -f "${POSTGRESQL_DATA_DIR}/${STANDBY_ALREADY_CLONED_FILENAME}" || -f "${POSTGRESQL_DATA_DIR}/${FORCE_UNSAFE_CLONE_FILENAME}" ]]; then
              repmgr_clone_primary
            fi
        else
            repmgr_rewind || exit $?
        fi
    fi

    if [[ -f "${POSTGRESQL_DATA_DIR}/${FORCE_UNSAFE_CLONE_FILENAME}" ]]; then
      warn "File ${POSTGRESQL_DATA_DIR}/${FORCE_UNSAFE_CLONE_FILENAME} still exists, so we delete it for the safety reason."
      rm "${POSTGRESQL_DATA_DIR}/${FORCE_UNSAFE_CLONE_FILENAME}"
    fi

    postgresql_initialize
    # Allow remote connections, required to register primary and standby nodes
    postgresql_enable_remote_connections
    # Configure port and restrict access to PostgreSQL (MD5)
    postgresql_set_property "port" "$POSTGRESQL_PORT_NUMBER"

    postgresql_configure_replication_parameters
    postgresql_configure_fsync

    is_boolean_yes "$REPMGR_PGHBA_TRUST_ALL" || postgresql_restrict_pghba
    if [[ "$REPMGR_NODE_TYPE" = "witness" ]]; then
      if [[ ! -f "$POSTGRESQL_DATA_DIR/$WITNESS_ALREADY_STARTED_FILENAME" ]]; then
            repmgr_wait_primary_node || exit 1
            postgresql_start_bg
            repmgr_create_repmgr_user
            repmgr_create_repmgr_db
            # Restart PostgreSQL
            postgresql_stop
            postgresql_start_bg
            repmgr_register_witness
            date --rfc-3339=ns > "$POSTGRESQL_DATA_DIR/$WITNESS_ALREADY_STARTED_FILENAME"
      fi
    elif [[ "$REPMGR_ROLE" = "primary" ]]; then
        if is_boolean_yes "$POSTGRESQL_FIRST_BOOT"; then
            postgresql_start_bg
            repmgr_create_repmgr_user
            repmgr_create_repmgr_db
            # Restart PostgreSQL
            postgresql_stop
            postgresql_start_bg
            repmgr_register_primary
            # Allow running custom initialization scripts
            postgresql_custom_init_scripts
        elif is_boolean_yes "$REPMGR_UPGRADE_EXTENSION"; then
            # Upgrade repmgr extension
            postgresql_start_bg
            repmgr_upgrade_extension
        else
            debug "Skipping repmgr configuration..."
        fi
        date --rfc-3339=ns > "${POSTGRESQL_DATA_DIR}/${STANDBY_ALREADY_CLONED_FILENAME}"
    else
        local -r psql_major_version="$(postgresql_get_major_version)"

        POSTGRESQL_MASTER_PORT_NUMBER="$REPMGR_CURRENT_PRIMARY_PORT"
        export POSTGRESQL_MASTER_PORT_NUMBER
        POSTGRESQL_MASTER_HOST="$REPMGR_CURRENT_PRIMARY_HOST"
        export POSTGRESQL_MASTER_HOST

        postgresql_configure_recovery
        postgresql_start_bg
        repmgr_unregister_standby
        repmgr_register_standby

        repmgr_wait_for_resolve_replication_lag

        local should_follow
        if ! should_follow=$(should_follow_primary); then
          exit 7
        elif is_boolean_yes "$should_follow"; then
          repmgr_follow_primary
        fi
    fi
}
