#!/bin/bash
#
# Bitnami Postgresql Repmgr library

# shellcheck disable=SC1090
# shellcheck disable=SC1091

# Load Generic Libraries
. /libfile.sh
. /libfs.sh
. /liblog.sh
. /libos.sh
. /libvalidations.sh
. /libnet.sh

########################
# Overwrite info, debug, warn and error functions (liblog.sh)
########################
repmgr_info() {
    MODULE=repmgr info "${*}"
}
repmgr_debug() {
    MODULE=repmgr debug "${*}"
}
repmgr_warn() {
    MODULE=repmgr warn "${*}"
}
repmgr_error() {
    MODULE=repmgr error "${*}"
}

########################
# Loads global variables used on repmgr configuration.
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   Series of exports to be used as 'eval' arguments
#########################
repmgr_env() {
    cat <<"EOF"
# Paths
export REPMGR_BASE_DIR="/opt/bitnami/repmgr"
export REPMGR_CONF_DIR="${REPMGR_BASE_DIR}/conf"
export REPMGR_MOUNTED_CONF_DIR="${REPMGR_MOUNTED_CONF_DIR:-/bitnami/repmgr/conf}"
export REPMGR_TMP_DIR="${REPMGR_BASE_DIR}/tmp"
export REPMGR_EVENTS_DIR="${REPMGR_BASE_DIR}/events"
export REPMGR_PRIMARY_ROLE_LOCK_FILE_NAME="${REPMGR_TMP_DIR}/master.lock"
export REPMGR_STANDBY_ROLE_LOCK_FILE_NAME="${REPMGR_TMP_DIR}/standby.lock"
export REPMGR_BIN_DIR="${REPMGR_BASE_DIR}/bin"
export REPMGR_CONF_FILE="${REPMGR_CONF_DIR}/repmgr.conf"
export REPMGR_PID_FILE="${REPMGR_TMP_DIR}/repmgr.pid"
export PATH="${REPMGR_BIN_DIR}:$PATH"

# Settings
export REPMGR_NODE_TYPE="${REPMGR_NODE_TYPE:-database}"
export REPMGR_NODE_ID="${REPMGR_NODE_ID:-}"
export REPMGR_NODE_NAME="${REPMGR_NODE_NAME:-$(hostname)}"
export REPMGR_NODE_NETWORK_NAME="${REPMGR_NODE_NETWORK_NAME:-}"
export REPMGR_NODE_PRIORITY="${REPMGR_NODE_PRIORITY:-100}"

export REPMGR_PORT_NUMBER="${REPMGR_PORT_NUMBER:-5432}"
export REPMGR_LOG_LEVEL="${REPMGR_LOG_LEVEL:-NOTICE}"

export REPMGR_START_OPTIONS="${REPMGR_START_OPTIONS:-}"
export REPMGR_CONNECT_TIMEOUT="${REPMGR_CONNECT_TIMEOUT:-5}"
export REPMGR_RECONNECT_ATTEMPTS="${REPMGR_RECONNECT_ATTEMPTS:-3}"
export REPMGR_RECONNECT_INTERVAL="${REPMGR_RECONNECT_INTERVAL:-5}"

export REPMGR_WITNESS_NODE="${REPMGR_WITNESS_NODE:-}"
export REPMGR_WITNESS_PORT="${REPMGR_WITNESS_PORT:-5432}"
export REPMGR_PRIMARY_HOST="${REPMGR_PRIMARY_HOST:-}"
export REPMGR_PRIMARY_PORT="${REPMGR_PRIMARY_PORT:-5432}"

export REPMGR_USE_REPLICATION_SLOTS="${REPMGR_USE_REPLICATION_SLOTS:-1}"
export REPMGR_STANDBY_ROLE_LOCK_FILE_NAME="${REPMGR_TMP_DIR}/standby.lock"
export REPMGR_MASTER_RESPONSE_TIMEOUT="${REPMGR_MASTER_RESPONSE_TIMEOUT:-20}"
export REPMGR_DEGRADED_MONITORING_TIMEOUT="${REPMGR_DEGRADED_MONITORING_TIMEOUT:-5}"

export REPMGR_UPGRADE_EXTENSION="${REPMGR_UPGRADE_EXTENSION:-no}"

# These are internal
export REPMGR_SWITCH_ROLE="${REPMGR_SWITCH_ROLE:-no}"
export REPMGR_CURRENT_PRIMARY_HOST=""
export REPMGR_CURRENT_PRIMARY_PORT="${REPMGR_PRIMARY_PORT}"
export STANDBY_ALREADY_CLONED_FILENAME=".standbyAlreadyCloned"
export WITNESS_ALREADY_STARTED_FILENAME=".witnessAlreadyStarted"
export FORCE_UNSAFE_CLONE_FILENAME=".forceUnsafeClone"
export FORCE_RUN_PRIMARY_WITHOUT_WITNESS_FILENAME=".forceRunPrimaryWithoutWitness"


# Aliases to setup PostgreSQL environment variables
export PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-10}"

# Credentials
export REPMGR_USERNAME="${REPMGR_USERNAME:-repmgr}"
export REPMGR_DATABASE="${REPMGR_DATABASE:-repmgr}"
export REPMGR_PGHBA_TRUST_ALL="${REPMGR_PGHBA_TRUST_ALL:-no}"
EOF
if [[ -f "${REPMGR_PASSWORD_FILE:-}" ]]; then
    cat <<"EOF"
export REPMGR_PASSWORD="$(< "${REPMGR_PASSWORD_FILE}")"
EOF
else
    cat <<"EOF"
export REPMGR_PASSWORD="${REPMGR_PASSWORD:-}"
EOF
fi
}

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
# Validate settings in REPMGR_* env. variables
# Globals:
#   REPMGR_*
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_validate() {
    repmgr_info "Validating settings in REPMGR_* env vars..."
    local error_code=0

    # Auxiliary functions
    print_validation_error() {
        repmgr_error "$1"
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


    if [[ -n "$REPMGR_WITNESS_NODE" ]]; then
        repmgr_info "Searching primary node using witness..."
        host="$REPMGR_WITNESS_NODE"
        port="${REPMGR_WITNESS_PORT:-5432}"
        repmgr_debug "Checking witness '$host:$port'..."
        local query="SELECT conninfo FROM repmgr.show_nodes WHERE (upstream_node_name IS NULL OR upstream_node_name = '') AND active=true"
        if ! primary_conninfo="$(echo "$query" | NO_ERRORS=true postgresql_execute "$REPMGR_DATABASE" "$REPMGR_USERNAME" "$REPMGR_PASSWORD" "$host" "$port" "-tA")"; then
            repmgr_debug "Skipping: failed to get primary from the node '$host:$port'!"
        elif [[ -z "$primary_conninfo" ]]; then
            repmgr_debug "Skipping: failed to get information about primary nodes!"
        elif [[ "$(echo "$primary_conninfo" | wc -l)" -eq 1 ]]; then
            local -r suggested_primary_host="$(echo "$primary_conninfo" | awk -F 'host=' '{print $2}' | awk '{print $1}')"
            local -r suggested_primary_port="$(echo "$primary_conninfo" | awk -F 'port=' '{print $2}' | awk '{print $1}')"
            repmgr_debug "Pretending primary role node - '${suggested_primary_host}:${suggested_primary_port}'"
            if [[ -n "$pretending_primary_host" ]]; then
                if [[ "${pretending_primary_host}:${pretending_primary_port}" != "${suggested_primary_host}:${suggested_primary_port}" ]]; then
                    repmgr_warn "Conflict of pretending primary role nodes (previously: '${pretending_primary_host}:${pretending_primary_port}', now: '${suggested_primary_host}:${suggested_primary_port}')"
                    pretending_primary_host="" && pretending_primary_port=""
                fi
            else
                repmgr_debug "Pretending primary set to '${suggested_primary_host}:${suggested_primary_port}'!"
                pretending_primary_host="$suggested_primary_host"
                pretending_primary_port="$suggested_primary_port"
            fi
        else
            repmgr_warn "There were more than one primary when getting primary from node '$host:$port'"
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
    [[ -n "$upstream_host" ]] && repmgr_info "Auto-detected primary node: '${upstream_host}:${upstream_port}'"

    if [[ -f "$REPMGR_PRIMARY_ROLE_LOCK_FILE_NAME" ]]; then
        repmgr_info "This node was acting as a primary before restart!"

        if [[ -z "$upstream_host" ]] || [[ "${upstream_host}:${upstream_port}" = "${REPMGR_NODE_NETWORK_NAME}:${REPMGR_PORT_NUMBER}" ]]; then
            repmgr_info "Can not find new primary. Starting PostgreSQL normally..."
        else
            repmgr_info "Current master is '${upstream_host}:${upstream_port}'. Cloning/rewinding it and acting as a standby node..."
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

    [[ -n "$primary_host" ]] && repmgr_debug "Primary node: '${primary_host}:${primary_port}'"
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
        repmgr_info "There are no nodes with primary role. Assuming the primary role ($REPMGR_PRIMARY_HOST:$REPMGR_PRIMARY_PORT)..."
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
    repmgr_info "Creating repmgr user: $REPMGR_USERNAME"

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
    repmgr_info "Creating repmgr database: $REPMGR_DATABASE"

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
    repmgr_debug "Injecting a new postgresql.conf file..."
    postgresql_create_config
    # ref: https://repmgr.org/docs/4.3/quickstart-postgresql-configuration.html
    postgresql_set_property "shared_preload_libraries" "repmgr"
    postgresql_set_property "max_wal_senders" "10"
    postgresql_set_property "max_replication_slots" "10"
    postgresql_set_property "wal_level" "hot_standby"
    postgresql_set_property "archive_mode" "on"
    postgresql_set_property "hot_standby" "on"
    postgresql_set_property "archive_command" "/bin/true"
    # Redirect logs to POSTGRESQL_LOG_FILE
    postgresql_set_property "logging_collector" "on"
    postgresql_set_property "log_directory" "$POSTGRESQL_LOG_DIR"
    postgresql_set_property "log_filename" "postgresql.log"
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
    repmgr_debug "Injecting a new pg_hba.conf file..."

    cat > "${POSTGRESQL_MOUNTED_CONF_DIR}/pg_hba.conf" << EOF
host     all            $REPMGR_USERNAME    0.0.0.0/0    trust
host     $REPMGR_DATABASE         $REPMGR_USERNAME    0.0.0.0/0    trust
host     replication      $REPMGR_USERNAME    0.0.0.0/0    trust
host     all              all       0.0.0.0/0    trust
host     all              all       ::1/128      trust
local    all              all                    trust
EOF
}

########################
# Prepare PostgreSQL default configuration
# Globals:
#   POSTGRESQL_MOUNTED_CONF_DIR
#   REPMGR_MOUNTED_CONF_DIR
# Arguments:
#   None
# Returns:
#   None
#########################
repmgr_postgresql_configuration() {
    repmgr_info "Preparing PostgreSQL configuration..."
    # User injected custom configuration
    if [[ -d "$REPMGR_MOUNTED_CONF_DIR" ]] && compgen -G "$REPMGR_MOUNTED_CONF_DIR"/* > /dev/null; then
        repmgr_debug "User injected custom configuration detected!"
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
    repmgr_info "Preparing repmgr configuration..."

    if [[ -f "${REPMGR_MOUNTED_CONF_DIR}/repmgr.conf" ]]; then
        repmgr_info "Custom repmgr.conf file detected"
        cp "${REPMGR_MOUNTED_CONF_DIR}/repmgr.conf" "$REPMGR_CONF_FILE"
    else
        cat << EOF >> "$REPMGR_CONF_FILE"
event_notification_command='${REPMGR_EVENTS_DIR}/router.sh %n %e %s "%t" "%d"'
ssh_options='-o "StrictHostKeyChecking no" -v'
use_replication_slots='${REPMGR_USE_REPLICATION_SLOTS}'
pg_bindir='${POSTGRESQL_BIN_DIR}'

# FIXME: these 2 parameter should work
node_id=$(repmgr_get_node_id)
node_name='${REPMGR_NODE_NAME}'
conninfo='user=${REPMGR_USERNAME} password=${REPMGR_PASSWORD} host=${REPMGR_NODE_NETWORK_NAME} dbname=${REPMGR_DATABASE} port=${REPMGR_PORT_NUMBER} connect_timeout=${REPMGR_CONNECT_TIMEOUT}'
failover='automatic'
promote_command='PGPASSWORD=${REPMGR_PASSWORD} repmgr standby promote -f "${REPMGR_CONF_FILE}" --log-level DEBUG --verbose'
follow_command='PGPASSWORD=${REPMGR_PASSWORD} repmgr standby follow -f "${REPMGR_CONF_FILE}" -W --log-level DEBUG --verbose'
reconnect_attempts='${REPMGR_RECONNECT_ATTEMPTS}'
reconnect_interval='${REPMGR_RECONNECT_INTERVAL}'
log_level='${REPMGR_LOG_LEVEL}'
priority='${REPMGR_NODE_PRIORITY}'
degraded_monitoring_timeout='${REPMGR_DEGRADED_MONITORING_TIMEOUT}'
data_directory='${POSTGRESQL_DATA_DIR}'
pg_ctl_options='-l $POSTGRESQL_LOG_FILE -o --config-file="$POSTGRESQL_CONF_FILE --external_pid_file=$POSTGRESQL_PID_FILE --hba_file=$POSTGRESQL_PGHBA_FILE"'
async_query_timeout='${REPMGR_MASTER_RESPONSE_TIMEOUT}'
EOF
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
    repmgr_info "Waiting for $name node..."
    repmgr_debug "Wait for schema $REPMGR_DATABASE.repmgr on '${host}:${port}', will try $max_tries times with $step delay seconds (TIMEOUT=$timeout)"
    for ((i = 0 ; i <= timeout ; i+=step )); do
        local query="SELECT 1 FROM information_schema.schemata WHERE catalog_name='$REPMGR_DATABASE' AND schema_name='repmgr'"
        if ! schemata="$(echo "$query" | NO_ERRORS=true postgresql_execute "$REPMGR_DATABASE" "$REPMGR_USERNAME" "$REPMGR_PASSWORD" "$host" "$port" "-tA")"; then
            repmgr_debug "Host '${host}:${port}' is not accessible"
        else
            if [[ $schemata -ne 1 ]]; then
                repmgr_debug "Schema $REPMGR_DATABASE.repmgr is still not accessible"
            else
                repmgr_debug "Schema $REPMGR_DATABASE.repmgr exists!"
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
    repmgr_info "Getting replication lag..."
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
    repmgr_info "Waiting for resolve lag..."
    for ((i=0,current_try=1 ; i <= timeout ; i+=step,current_try++ )); do
        lag="$(repmgr_get_replication_lag)"
        local exit_code=$?
        if [[ $exit_code -ne 0 && $exit_code -ne 1 ]]; then
            repmgr_debug "[$current_try/$max_tries] Cannot get replication lag for this node (node return: $lag)"
        else
            if [[ "$lag" != "OK"* ]]; then
                repmgr_debug "[$current_try/$max_tries] Found lag on this node (node return: $lag)"
            else
                repmgr_debug "[$current_try/$max_tries] Lag is OK (node return: $lag)"
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
    repmgr_info "Cloning data from primary node..."
    local flags=("-f" "$REPMGR_CONF_FILE" "-h" "$REPMGR_CURRENT_PRIMARY_HOST" "-p" "$REPMGR_CURRENT_PRIMARY_PORT" "-U" "$REPMGR_USERNAME" "-d" "$REPMGR_DATABASE" "-D" "$POSTGRESQL_DATA_DIR" "standby" "clone" "--fast-checkpoint")

    if [[ -f "${POSTGRESQL_DATA_DIR}/${FORCE_UNSAFE_CLONE_FILENAME}" ]]; then
      rm "${POSTGRESQL_DATA_DIR}/${FORCE_UNSAFE_CLONE_FILENAME}" || exit $?
      flags+=( "--force" )
      repmgr_info "USE FORCE FLAG IN CLONE!!!"
    fi

    PGPASSWORD="$REPMGR_PASSWORD" debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
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
      repmgr_info "Rejoining node..."
      repmgr_debug "Cloning data from primary node with force flag..."
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
    repmgr_info "Registering Primary..."
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
    repmgr_info "Unregistering standby node..."

    local -r flags=("standby" "unregister" "-f" "$REPMGR_CONF_FILE" "--node-id=$(repmgr_get_node_id)")

    # The command below can fail when the node doesn't exist yet
    debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}" || true
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
    repmgr_info "Registering Standby node..."
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
    repmgr_info "Following primary node..."
    local -r flags=("standby" "follow" "-f" "$REPMGR_CONF_FILE" "--force" "--verbose")

    PGPASSWORD="$REPMGR_PASSWORD" debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
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
    repmgr_info "Registering Witness node..."
    local -r flags=("witness" "register" "-f" "$REPMGR_CONF_FILE" "--host" "$REPMGR_CURRENT_PRIMARY_HOST" "--port" "$REPMGR_CURRENT_PRIMARY_PORT" "--force" "--verbose")

    PGPASSWORD="$REPMGR_PASSWORD" debug_execute "${REPMGR_BIN_DIR}/repmgr" "${flags[@]}"
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
    repmgr_info "Upgrading repmgr extension..."

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
    repmgr_info "Checking node(role: $REPMGR_ROLE) replication slots..."

    local -r query="SELECT count(*) from pg_replication_slots s LEFT JOIN nodes n ON s.slot_name=n.slot_name WHERE n.node_id=$(repmgr_get_node_id);"
    if ! count_replication_slots="$(echo "$query" | NO_ERRORS=true postgresql_execute "$REPMGR_DATABASE" "$REPMGR_USERNAME" "$REPMGR_PASSWORD" "$REPMGR_CURRENT_PRIMARY_HOST" "$REPMGR_CURRENT_PRIMARY_PORT" "-tA")"; then
        repmgr_warn "Failed to check replication slot from the node '$host:$port'!"
        exit 5
    elif [[ -z "$count_replication_slots" ]]; then
        repmgr_warn "Failed to get information about replication slot!"
        exit 6
    else
      repmgr_debug "Replication slots found for this node: $count_replication_slots"
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

    repmgr_debug "Node ID: '$(repmgr_get_node_id)', Rol: '$REPMGR_ROLE', Primary Node: '${REPMGR_CURRENT_PRIMARY_HOST}:${REPMGR_CURRENT_PRIMARY_PORT}'"
    repmgr_info "Initializing Repmgr..."

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
      repmgr_warn "File ${POSTGRESQL_DATA_DIR}/${FORCE_UNSAFE_CLONE_FILENAME} still exists, so we delete it for the safety reason."
      rm "${POSTGRESQL_DATA_DIR}/${FORCE_UNSAFE_CLONE_FILENAME}"
    fi

    postgresql_initialize
    # Allow remote connections, required to register primary and standby nodes
    postgresql_enable_remote_connections
    # Configure port and restrict access to PostgreSQL (MD5)
    postgresql_set_property "port" "$POSTGRESQL_PORT_NUMBER"
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
            repmgr_debug "Skipping repmgr configuration..."
        fi
        date --rfc-3339=ns > "${POSTGRESQL_DATA_DIR}/${STANDBY_ALREADY_CLONED_FILENAME}"
    else
        (( POSTGRESQL_MAJOR_VERSION >= 12 )) && postgresql_configure_recovery
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
