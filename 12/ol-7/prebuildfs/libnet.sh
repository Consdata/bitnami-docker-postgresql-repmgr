#!/bin/bash
#
# Library for network functions

# Functions

########################
# Resolve dns
# Arguments:
#   $1 - Hostname to resolve
# Returns:
#   IP
#########################
dns_lookup() {
    local host="${1:?host is missing}"
    getent ahosts "$host" | awk '/STREAM/ {print $1 }'
}

########################
# Get machine's IP
# Arguments:
#   None
# Returns:
#   Machine IP
#########################
get_machine_ip() {
    dns_lookup "$(hostname)"
}

########################
# Check if the provided argument is a resolved hostname
# Arguments:
#   $1 - Value to check
# Returns:
#   Boolean
#########################
is_hostname_resolved() {
    local -r host="${1:?missing value}"
    if [[ -n "$(dns_lookup "$host")" ]]; then
        true
    else
        false
    fi
}

########################
# Parse URL
# Globals:
#   None
# Arguments:
#   $1 - url - String
#   $2 - field to obtain. Valid options (protocol, hostname, or port) - String
# Returns:
#   String
parse_url() {
	local url=$1
	local field_to_obtain=$2

	if [[ "$field_to_obtain" == "protocol" ]]; then
	  local extracted_protocol=$([[ "$url" = *'://'* ]] && echo "${url%://*}" || echo '')
	  echo "$extracted_protocol"
	fi
	if [[ "$field_to_obtain" == "hostname" ]]; then
    local extracted_hostname="${url##*'://'}"
    extracted_hostname="${extracted_hostname%:*}"
	  echo "$extracted_hostname"
	fi
	if [[ "$field_to_obtain" == "port" ]]; then
	  local extracted_port="${url##*'://'}"
	  extracted_port=$([[ "$extracted_port" = *':'* ]] && echo "${extracted_port##*':'}" || echo "$default_port")
	  echo "$extracted_port"
	fi
  echo ''
}