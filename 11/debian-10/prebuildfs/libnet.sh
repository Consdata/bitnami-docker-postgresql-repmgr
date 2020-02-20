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
# Check that node_address can be IPv6 format
# Arguments:
#   $1 - node_address - String
# Returns:
#   Boolean
#########################
canBeIPv6() {
	[[ $(echo $1  | grep -o ':' | wc -l) -ge 2 ]]
}

########################
# Extract host and port from address
# Globals:
#   None
# Arguments:
#   $1 - node_address - String
#   $2 - default_port - Integer
# Returns:
#   Array - (host port)
#########################
extractHostAndPort() {
	local node_address=$1
	local default_port=$2
	local extracted_host=$node_address;
	local extracted_port=$default_port;

	if canBeIPv6 $node_address; then
		if [[ $node_address =~ ^\[[^\]]+\]:[0-9]+$ ]]; then
			extracted_host="${node_address%']'*}"
			extracted_host="${extracted_host##*'['}"

			extracted_port=$([[ "$node_address" = *']:'* ]] && echo "${node_address##*']:'}" || echo "$default_port")
			extracted_port=${extracted_port:-default_port}
		fi
	else
		extracted_host="${node_address%:*}"

		extracted_port=$([[ "$node_address" = *':'* ]] && echo "${node_address##*':'}" || echo "$default_port")
		extracted_port=${extracted_port:-default_port}
	fi
	echo $extracted_host
	echo $extracted_port
}
