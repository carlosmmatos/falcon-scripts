#!/bin/bash

VERSION="1.0.0"

# Default log file and recovery file paths
LOG_FILE="/var/log/falcon_migrate.log"
RECOVERY_FILE="/var/run/falcon_migrate_recovery.json"

# Function to log messages to console and log file
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Create log message with timestamp
    local log_message="[${timestamp}] [${level}] ${message}"
    
    # Print to console
    echo "$log_message"
    
    # Append to log file if set
    if [ -n "$LOG_FILE" ]; then
        echo "$log_message" >> "$LOG_FILE"
    fi
}

# Function to log info level messages
log_info() {
    log "INFO" "$1"
}

# Function to log warning level messages
log_warning() {
    log "WARNING" "$1"
}

# Function to log error level messages
log_error() {
    log "ERROR" "$1"
}

# Function to save recovery information
save_recovery_info() {
    if [ -n "$RECOVERY_FILE" ]; then
        # Create JSON structure with important recovery information
        cat > "$RECOVERY_FILE" <<EOF
{
  "timestamp": "$(date +"%Y-%m-%d %H:%M:%S")",
  "aid": "$aid",
  "tags": $( [ -n "$existing_tags" ] && echo "\"$existing_tags\"" || echo "null" ),
  "cid": "$new_cid"
}
EOF
        log_info "Saved recovery information to $RECOVERY_FILE"
    fi
}

# Function to load recovery information if available
load_recovery_info() {
    if [ -f "$RECOVERY_FILE" ]; then
        log_info "Found recovery file $RECOVERY_FILE, loading data"
        
        # Parse the recovery file to extract data
        recovered_aid=$(grep -o '"aid":.*",' "$RECOVERY_FILE" | cut -d'"' -f4)
        recovered_tags=$(grep -o '"tags":.*",' "$RECOVERY_FILE" | cut -d'"' -f4 || echo "")
        recovered_cid=$(grep -o '"cid":.*"' "$RECOVERY_FILE" | cut -d'"' -f4)
        
        if [ -n "$recovered_aid" ]; then
            log_info "Recovered AID: $recovered_aid"
            aid="$recovered_aid"
        fi
        
        if [ -n "$recovered_tags" ] && [ "$recovered_tags" != "null" ]; then
            log_info "Recovered tags: $recovered_tags"
            existing_tags="$recovered_tags"
        fi
        
        if [ -n "$recovered_cid" ]; then
            log_info "Recovered CID: $recovered_cid"
            new_cid="$recovered_cid"
        fi
        
        return 0
    else
        log_info "No recovery file found at $RECOVERY_FILE"
        return 1
    fi
}

# Function to handle fatal errors
die() {
    log_error "$1"
    exit 1
}

# Handle CURL errors
handle_curl_error() {
    local exit_code=$1
    if [ "$exit_code" -ne 0 ]; then
        if [ "$exit_code" -eq 7 ]; then
            log_error "Failed to connect to server. Please check your network connectivity and proxy settings."
        elif [ "$exit_code" -eq 22 ]; then
            log_error "HTTP error from server. The server rejected the request."
        elif [ "$exit_code" -eq 28 ]; then
            log_error "Connection timed out. Server might be unreachable."
        else
            log_error "CURL error code: $exit_code. Please check your connectivity."
        fi
        return 1
    fi
    return 0
}

print_usage() {
    cat <<EOF

Usage: $0 [-h|--help]

Migrates the CrowdStrike Falcon Sensor from one CID to another.
Version: $VERSION

This script recognizes the following environmental variables:

Existing CID Authentication:
    - EXISTING_FALCON_CLIENT_ID                (default: unset)
        Your existing CrowdStrike Falcon API client ID.

    - EXISTING_FALCON_CLIENT_SECRET            (default: unset)
        Your existing CrowdStrike Falcon API client secret.

    - EXISTING_FALCON_ACCESS_TOKEN             (default: unset)
        Your existing CrowdStrike Falcon API access token.
        If used, EXISTING_FALCON_CLOUD must also be set.

    - EXISTING_FALCON_CLOUD                    (default: unset)
        The cloud region where your existing CrowdStrike Falcon instance is hosted.
        Required if using EXISTING_FALCON_ACCESS_TOKEN.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1'].

New CID Authentication:
    - NEW_FALCON_CLIENT_ID                     (default: unset)
        Your new CrowdStrike Falcon API client ID.

    - NEW_FALCON_CLIENT_SECRET                 (default: unset)
        Your new CrowdStrike Falcon API client secret.

    - NEW_FALCON_ACCESS_TOKEN                  (default: unset)
        Your new CrowdStrike Falcon API access token.
        If used, NEW_FALCON_CLOUD must also be set.

    - NEW_FALCON_CLOUD                         (default: unset)
        The cloud region where your new CrowdStrike Falcon instance is hosted.
        Required if using NEW_FALCON_ACCESS_TOKEN.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1'].

Migration Options:
    - MIGRATE_TAGS                             (default: false)
        Migrate the host's existing tags to the new CID.
        Accepted values are ['true', 'false'].

    - NEW_FALCON_TAGS                          (default: unset)
        A comma separated list of tags for the sensor in the new CID.
        If MIGRATE_TAGS is true, these tags will be added in addition to the existing tags.

Other Options:
    - FALCON_MAINTENANCE_TOKEN                 (default: unset)
        Sensor uninstall maintenance token used to unlock sensor uninstallation.
        If not provided, the script will try to retrieve it from the API.

    - FALCON_PROVISIONING_TOKEN                (default: unset)
        The provisioning token to use for installing the sensor in the new CID.
        If not provided, the script will try to retrieve it from the API.

    - FALCON_SENSOR_UPDATE_POLICY_NAME         (default: unset)
        The name of the sensor update policy to use for installing the sensor.

    - FALCON_APD                               (default: unset)
        Configures if the proxy should be enabled or disabled.

    - FALCON_APH                               (default: unset)
        The proxy host for the sensor to use when communicating with CrowdStrike.

    - FALCON_APP                               (default: unset)
        The proxy port for the sensor to use when communicating with CrowdStrike.

    - FALCON_BILLING                           (default: default)
        To configure the sensor billing type.
        Accepted values are [default|metered].

    - FALCON_BACKEND                           (default: auto)
        For sensor backend.
        Accepted values are [auto|bpf|kernel].

    - FALCON_TRACE                             (default: none)
        To configure the trace level.
        Accepted values are [none|err|warn|info|debug]

    - ALLOW_LEGACY_CURL                        (default: false)
        To use the legacy version of curl; version < 7.55.0.

    - USER_AGENT                               (default: unset)
        User agent string to append to the User-Agent header when making
        requests to the CrowdStrike API.

This script recognizes the following argument:
    -h, --help
        Print this help message and exit.

EOF
}

# If -h or --help is passed, print the usage and exit
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    print_usage
    exit 0
fi

# Function to set up all required variables
setup_variables() {
    log_info "Setting up variables for migration..."
    
    # Try to load recovery information from a previous run
    load_recovery_info
    
    # Detect OS information
    detect_os
    
    # Set default values if not already set
    MIGRATE_TAGS="${MIGRATE_TAGS:-false}"
    
    # Log configuration
    log_info "Migration configuration:"
    log_info "OS: ${os_name} ${cs_os_version}"
    log_info "Migrate tags: ${MIGRATE_TAGS}"
    if [ -n "$NEW_FALCON_TAGS" ]; then
        log_info "New tags: ${NEW_FALCON_TAGS}"
    fi
}

# Detect OS name and version
detect_os() {
    log_info "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        os_name="$NAME"
        cs_os_version="$VERSION_ID"
        cs_os_name="$ID"
    elif type lsb_release >/dev/null 2>&1; then
        os_name=$(lsb_release -s -d)
        cs_os_version=$(lsb_release -s -r)
        cs_os_name=$(lsb_release -s -i | tr '[:upper:]' '[:lower:]')
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        os_name="$DISTRIB_DESCRIPTION"
        cs_os_version="$DISTRIB_RELEASE"
        cs_os_name="$DISTRIB_ID"
    elif [ -f /etc/redhat-release ]; then
        os_name=$(cat /etc/redhat-release)
        cs_os_version=$(cat /etc/redhat-release | grep -oE '[0-9]+\.[0-9]+' | head -n1)
        cs_os_name="rhel"
    else
        log_error "Unsupported OS: Could not determine operating system."
        exit 1
    fi
    
    # Get architecture
    cs_os_arch=$(uname -m)
    
    # Set os_arch_filter for API calls
    if [ "$cs_os_arch" = "x86_64" ]; then
        cs_os_arch_filter="+arch:\"x86_64\""
    elif [ "$cs_os_arch" = "aarch64" ]; then
        cs_os_arch_filter="+arch:\"aarch64\""
    else
        log_warning "Unsupported architecture: $cs_os_arch. Proceeding without architecture filter."
        cs_os_arch_filter=""
    fi
    
    log_info "Detected OS: $os_name $cs_os_version ($cs_os_arch)"
}

# Get authentication token for existing CID
existing_get_oauth_token() {
    log_info "Getting OAuth token for existing CID..."
    
    if [ -n "$EXISTING_FALCON_ACCESS_TOKEN" ]; then
        log_info "Using existing access token from environment variable."
        cs_falcon_oauth_token="$EXISTING_FALCON_ACCESS_TOKEN"
        return 0
    fi
    
    if [ -z "$EXISTING_FALCON_CLIENT_ID" ] || [ -z "$EXISTING_FALCON_CLIENT_SECRET" ]; then
        log_error "Missing required credentials. EXISTING_FALCON_CLIENT_ID and EXISTING_FALCON_CLIENT_SECRET must be set."
        exit 1
    fi
    
    if [ -z "$EXISTING_FALCON_CLOUD" ]; then
        EXISTING_FALCON_CLOUD="us-1"
        log_warning "EXISTING_FALCON_CLOUD not set, defaulting to us-1"
    fi
    
    # Set cloud-specific API endpoint
    case "$EXISTING_FALCON_CLOUD" in
        us-1)
            cs_cloud="api.crowdstrike.com"
            ;;
        us-2)
            cs_cloud="api.us-2.crowdstrike.com"
            ;;
        eu-1)
            cs_cloud="api.eu-1.crowdstrike.com"
            ;;
        us-gov-1)
            cs_cloud="api.laggar.gcw.crowdstrike.com"
            ;;
        *)
            log_error "Unsupported cloud: $EXISTING_FALCON_CLOUD. Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1']"
            exit 1
            ;;
    esac
    
    # Get the token
    token_response=$(curl_command -s -L -X POST "https://$cs_cloud/oauth2/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=$EXISTING_FALCON_CLIENT_ID&client_secret=$EXISTING_FALCON_CLIENT_SECRET")
    
    if ! handle_curl_error $?; then
        log_error "Failed to get OAuth token for existing CID."
        exit 1
    fi
    
    cs_falcon_oauth_token=$(echo "$token_response" | json_value "access_token" | sed 's/"//g')
    
    if [ -z "$cs_falcon_oauth_token" ]; then
        log_error "Failed to get OAuth token: $token_response"
        exit 1
    fi
    
    log_info "Successfully obtained OAuth token for existing CID."
}

# Get authentication token for new CID
new_get_oauth_token() {
    log_info "Getting OAuth token for new CID..."
    
    if [ -n "$NEW_FALCON_ACCESS_TOKEN" ]; then
        log_info "Using new access token from environment variable."
        target_cs_falcon_oauth_token="$NEW_FALCON_ACCESS_TOKEN"
        return 0
    fi
    
    if [ -z "$NEW_FALCON_CLIENT_ID" ] || [ -z "$NEW_FALCON_CLIENT_SECRET" ]; then
        log_error "Missing required credentials. NEW_FALCON_CLIENT_ID and NEW_FALCON_CLIENT_SECRET must be set."
        exit 1
    fi
    
    if [ -z "$NEW_FALCON_CLOUD" ]; then
        NEW_FALCON_CLOUD="us-1"
        log_warning "NEW_FALCON_CLOUD not set, defaulting to us-1"
    fi
    
    # Set cloud-specific API endpoint
    case "$NEW_FALCON_CLOUD" in
        us-1)
            target_cs_cloud="api.crowdstrike.com"
            ;;
        us-2)
            target_cs_cloud="api.us-2.crowdstrike.com"
            ;;
        eu-1)
            target_cs_cloud="api.eu-1.crowdstrike.com"
            ;;
        us-gov-1)
            target_cs_cloud="api.laggar.gcw.crowdstrike.com"
            ;;
        *)
            log_error "Unsupported cloud: $NEW_FALCON_CLOUD. Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1']"
            exit 1
            ;;
    esac
    
    # Get the token
    token_response=$(curl_command -s -L -X POST "https://$target_cs_cloud/oauth2/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=$NEW_FALCON_CLIENT_ID&client_secret=$NEW_FALCON_CLIENT_SECRET")
    
    if ! handle_curl_error $?; then
        log_error "Failed to get OAuth token for new CID."
        exit 1
    fi
    
    target_cs_falcon_oauth_token=$(echo "$token_response" | json_value "access_token" | sed 's/"//g')
    
    if [ -z "$target_cs_falcon_oauth_token" ]; then
        log_error "Failed to get OAuth token: $token_response"
        exit 1
    fi
    
    log_info "Successfully obtained OAuth token for new CID."
}

# Basic curl command with user agent
curl_command() {
    user_agent="falcon-migration-script/${VERSION}"
    if [ -n "$USER_AGENT" ]; then
        user_agent="${user_agent} ${USER_AGENT}"
    fi
    
    curl --silent --show-error --connect-timeout 60 -A "$user_agent" "$@"
}

# Target curl command (with target token)
target_curl_command() {
    if [ -z "$target_cs_falcon_oauth_token" ]; then
        log_error "Target OAuth token not set. Run new_get_oauth_token first."
        exit 1
    fi
    
    curl_command -H "Authorization: Bearer $target_cs_falcon_oauth_token" "$@"
}

# Source curl command (with source token)
source_curl_command() {
    if [ -z "$cs_falcon_oauth_token" ]; then
        log_error "Source OAuth token not set. Run existing_get_oauth_token first."
        exit 1
    fi
    
    curl_command -H "Authorization: Bearer $cs_falcon_oauth_token" "$@"
}

# Helper function to parse JSON responses
json_value() {
    local key="$1" index="${2:-1}"
    local js
    
    # Read JSON from stdin if available
    if [ ! -t 0 ]; then
        js=$(cat)
    else
        js="$3"
    fi
    
    # Extract value with jq if available
    if type jq >/dev/null 2>&1; then
        echo "$js" | jq -r ".resources[$((index - 1))].$key // empty"
        return
    fi
    
    # Fallback to awk/sed for basic extraction
    echo "$js" | grep -o "\"$key\":[^,}]*" | sed -e "s/\"$key\"://" -e 's/^[ \t]*//' | head -n "$index" | tail -n 1
}

# Get existing tags from the source CID
get_existing_tags() {
    log_info "Retrieving existing tags for host with AID: $aid"
    
    if [ -z "$aid" ]; then
        log_warning "Cannot retrieve tags: AID is not available."
        return 1
    fi
    
    if [ -z "$cs_falcon_oauth_token" ]; then
        log_warning "Cannot retrieve tags: Source OAuth token is not available."
        return 1
    fi
    
    # Get host details from API to retrieve tags
    host_response=$(source_curl_command "https://$cs_cloud/devices/entities/devices/v1?ids=$aid")
    
    if ! handle_curl_error $?; then
        log_warning "Failed to retrieve host details from API."
        return 1
    fi
    
    # Extract tags from the host response
    existing_tags=$(echo "$host_response" | grep -o '"tags":\[[^]]*\]' | sed -e 's/"tags"://' -e 's/\[//' -e 's/\]//' -e 's/"//g' -e 's/,/,/g')
    
    if [ -n "$existing_tags" ]; then
        log_info "Retrieved tags: $existing_tags"
        
        # Save recovery information
        save_recovery_info
        
        # If we need to combine with NEW_FALCON_TAGS
        if [ -n "$NEW_FALCON_TAGS" ]; then
            FALCON_TAGS="${existing_tags},${NEW_FALCON_TAGS}"
            log_info "Combined tags: $FALCON_TAGS"
        else
            FALCON_TAGS="$existing_tags"
        fi
    else
        log_warning "No tags found for host with AID: $aid"
        if [ -n "$NEW_FALCON_TAGS" ]; then
            FALCON_TAGS="$NEW_FALCON_TAGS"
        fi
    fi
}

# Get maintenance token for uninstalling sensor
get_maintenance_token() {
    log_info "Retrieving maintenance token from API..."
    
    if [ -z "$aid" ]; then
        log_error "Cannot get maintenance token: AID is not available."
        exit 1
    fi
    
    if [ -z "$cs_falcon_oauth_token" ]; then
        log_error "Cannot get maintenance token: Source OAuth token is not available."
        exit 1
    fi
    
    # Call the maintenance token API
    token_response=$(source_curl_command -X POST "https://$cs_cloud/policy/entities/reveal-uninstall-token/v1" \
        -H "Content-Type: application/json" \
        -d "{\"audit_message\":\"Automated uninstall for CID migration\",\"device_id\":\"$aid\"}")
    
    if ! handle_curl_error $?; then
        log_error "Failed to retrieve maintenance token from API."
        exit 1
    fi
    
    cs_maintenance_token=$(echo "$token_response" | grep -o '"uninstall_token":"[^"]*"' | sed -e 's/"uninstall_token":"//' -e 's/"//')
    
    if [ -z "$cs_maintenance_token" ]; then
        log_error "Failed to extract maintenance token from response: $token_response"
        exit 1
    fi
    
    log_info "Successfully retrieved maintenance token."
}

# Get new CID from the target environment
get_new_falcon_cid() {
    log_info "Retrieving CID from target environment..."
    
    if [ -z "$target_cs_falcon_oauth_token" ]; then
        log_error "Cannot get CID: Target OAuth token is not available."
        exit 1
    fi
    
    # Call the sensor-installers API to get CID
    cid_response=$(target_curl_command "https://$target_cs_cloud/sensors/queries/installers/ccid/v1")
    
    if ! handle_curl_error $?; then
        log_error "Failed to retrieve CID from target environment."
        exit 1
    fi
    
    cid=$(echo "$cid_response" | grep -o '"resources":\["[^"]*"\]' | sed -e 's/"resources":\["//' -e 's/"\]//')
    
    if [ -z "$cid" ]; then
        log_error "Failed to extract CID from response: $cid_response"
        exit 1
    fi
    
    log_info "Successfully retrieved CID: $cid"
    save_recovery_info
    
    echo "$cid"
}

# Get provisioning token from the target environment
get_new_provisioning_token() {
    log_info "Checking if provisioning token is required..."
    
    # First check if provisioning is required
    prov_check=$(target_curl_command "https://$target_cs_cloud/sensors/queries/provisioning/v1")
    
    if ! handle_curl_error $?; then
        log_warning "Failed to check provisioning status. Continuing without token."
        return 1
    fi
    
    is_required=$(echo "$prov_check" | grep -o '"resources":\[[^]]*\]' | grep -o "true")
    
    if [ "$is_required" != "true" ]; then
        log_info "Provisioning token is not required."
        return 0
    fi
    
    log_info "Provisioning token is required. Generating token..."
    
    # Generate a provisioning token
    token_response=$(target_curl_command -X POST "https://$target_cs_cloud/sensors/entities/provisioning-token/v1" \
        -H "Content-Type: application/json" \
        -d "{\"expiration_days\":6,\"label\":\"Migration - $(date +"%Y-%m-%d")\"}")
    
    if ! handle_curl_error $?; then
        log_error "Failed to generate provisioning token."
        exit 1
    fi
    
    token=$(echo "$token_response" | grep -o '"token":[^,}]*' | sed -e 's/"token"://' -e 's/"//g')
    
    if [ -z "$token" ]; then
        log_error "Failed to extract provisioning token from response: $token_response"
        exit 1
    fi
    
    log_info "Successfully generated provisioning token."
    echo "$token"
}

# Main function to orchestrate the migration process
main() {
    log_info "Starting Falcon Sensor migration from existing CID to new CID..."
    
    # Initialize variables and settings
    setup_variables
    
    # Check if Falcon sensor is installed
    log_info "Checking if Falcon Sensor is running..."
    cs_sensor_is_running
    log_info "Falcon Sensor is running."
    
    # Get existing info before uninstall
    log_info "Getting existing sensor information..."
    get_existing_sensor_info
    log_info "Successfully retrieved sensor information."
    
    # Save recovery information before uninstall
    save_recovery_info
    
    # Uninstall current sensor
    log_info "Uninstalling existing Falcon Sensor..."
    uninstall_existing_sensor
    log_info "Successfully uninstalled Falcon Sensor."
    
    # Install sensor with new CID
    log_info "Installing Falcon Sensor with new CID..."
    install_new_sensor
    log_info "Successfully installed Falcon Sensor."
    
    # Register and restart sensor
    log_info "Registering Falcon Sensor..."
    register_sensor
    log_info "Successfully registered Falcon Sensor."
    
    log_info "Restarting Falcon Sensor..."
    restart_sensor
    log_info "Successfully restarted Falcon Sensor."
    
    # Verify installation by checking if sensor is running
    log_info "Verifying sensor installation..."
    if pgrep -u root falcon-sensor >/dev/null 2>&1; then
        log_info "Verification successful: Falcon sensor is running."
    else
        log_warning "Verification failed: Falcon sensor is not running after installation."
        log_warning "Please check the system logs for more information."
    fi
    
    # Clean up recovery file after successful migration
    if [ -f "$RECOVERY_FILE" ]; then
        log_info "Migration completed successfully, removing recovery file."
        rm -f "$RECOVERY_FILE"
    fi
    
    log_info "Falcon Sensor successfully migrated to new CID."
    log_info "Migration log file: $LOG_FILE"
}

# Function to check if sensor is running
cs_sensor_is_running() {
    if ! pgrep -u root falcon-sensor >/dev/null 2>&1; then
        echo "Falcon sensor is not running. Please ensure the sensor is installed and running before migration."
        exit 1
    fi
    
    # Get the AID for maintenance token retrieval and tag migration
    get_aid
}

# Get the AID of the installed sensor
get_aid() {
    aid="$(/opt/CrowdStrike/falconctl -g --aid | awk -F '"' '{print $2}')"
    if [ -z "$aid" ]; then
        echo "Warning: Unable to retrieve AID from the sensor."
    else
        echo "Found sensor with AID: $aid"
    fi
}

# Get sensor information from the existing CID (including tags)
get_existing_sensor_info() {
    # Set up the existing credentials
    echo "Setting up existing credentials..."
    existing_get_oauth_token
    
    # Get existing tags if tag migration is enabled
    if [ "${MIGRATE_TAGS}" = "true" ] && [ -n "$aid" ]; then
        echo "Retrieving existing tags for host with AID: $aid"
        get_existing_tags
    fi
}

# Uninstall the existing sensor
uninstall_existing_sensor() {
    # We need existing authentication to get maintenance token
    if [ -z "$FALCON_MAINTENANCE_TOKEN" ]; then
        echo "No maintenance token provided, retrieving from API..."
        get_maintenance_token
    else
        cs_maintenance_token="$FALCON_MAINTENANCE_TOKEN"
    fi
    
    # Execute the sensor removal
    cs_sensor_remove
}

# Remove the Falcon sensor
cs_sensor_remove() {
    # Handle maintenance protection
    if [ -n "$cs_maintenance_token" ]; then
        echo "Applying maintenance token..."
        if ! /opt/CrowdStrike/falconctl -s -f --maintenance-token="${cs_maintenance_token}" >/dev/null 2>&1; then
            die "Failed to apply maintenance token. Uninstallation may fail."
        fi
    fi

    # Check for package manager lock prior to uninstallation
    check_package_manager_lock
    
    echo "Removing Falcon sensor package..."
    remove_package "falcon-sensor"
}

# Check for package manager locks
check_package_manager_lock() {
    lock_file="/var/lib/rpm/.rpm.lock"
    lock_type="RPM"
    local timeout=300 interval=5 elapsed=0

    if type dpkg >/dev/null 2>&1; then
        lock_file="/var/lib/dpkg/lock"
        lock_type="DPKG"
    fi

    while lsof -w "$lock_file" >/dev/null 2>&1; do
        if [ $elapsed -eq 0 ]; then
            echo ""
            echo "Package manager is locked. Waiting up to ${timeout} seconds for lock to be released..."
        fi

        if [ $elapsed -ge $timeout ]; then
            echo "Timed out waiting for ${lock_type} lock to be released after ${timeout} seconds."
            echo "You may need to manually investigate processes locking ${lock_file}:"
            lsof -w "$lock_file" || true
            die "Installation aborted due to package manager lock timeout."
        fi

        sleep $interval
        elapsed=$((elapsed + interval))
        echo "Retrying again in ${interval} seconds..."
    done
}

# Remove package based on the OS
remove_package() {
    pkg="$1"

    if type dnf >/dev/null 2>&1; then
        dnf remove -q -y "$pkg" || rpm -e --nodeps "$pkg"
    elif type yum >/dev/null 2>&1; then
        yum remove -q -y "$pkg" || rpm -e --nodeps "$pkg"
    elif type zypper >/dev/null 2>&1; then
        zypper --quiet remove -y "$pkg" || rpm -e --nodeps "$pkg"
    elif type apt >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt purge -y "$pkg" >/dev/null 2>&1
    else
        rpm -e --nodeps "$pkg"
    fi
}

# Install sensor with new CID
install_new_sensor() {
    # Switch to new credentials
    echo "Setting up new credentials..."
    new_get_oauth_token
    
    # Get new CID
    new_cid=$(get_new_falcon_cid)
    echo "New CID: $new_cid"
    
    # Get provisioning token if needed
    if [ -z "$FALCON_PROVISIONING_TOKEN" ]; then
        echo "No provisioning token provided, checking if one is required..."
        new_provisioning_token=$(get_new_provisioning_token)
        if [ -n "$new_provisioning_token" ]; then
            FALCON_PROVISIONING_TOKEN="$new_provisioning_token"
            echo "Retrieved provisioning token from new CID."
        fi
    fi
    
    # Download and install the sensor
    cs_sensor_install
}

# Install the Falcon sensor
cs_sensor_install() {
    local tempdir package_name
    tempdir=$(mktemp -d)

    tempdir_cleanup() { rm -rf "$tempdir"; }
    trap tempdir_cleanup EXIT

    package_name=$(cs_sensor_download "$tempdir")
    os_install_package "$package_name"

    tempdir_cleanup
}

# Download the sensor installer
cs_sensor_download() {
    local destination_dir="$1" existing_installers sha_list INDEX sha file_type installer
    local cs_falcon_sensor_version_dec=${FALCON_SENSOR_VERSION_DECREMENT:-0}
    local cs_api_version_filter=""

    if [ -n "$FALCON_SENSOR_UPDATE_POLICY_NAME" ]; then
        cs_sensor_version=$(cs_sensor_policy_version "$FALCON_SENSOR_UPDATE_POLICY_NAME")
        cs_api_version_filter="+version:\"$cs_sensor_version\""

        if [ "$cs_falcon_sensor_version_dec" -gt 0 ]; then
            echo "WARNING: Disabling FALCON_SENSOR_VERSION_DECREMENT because it conflicts with FALCON_SENSOR_UPDATE_POLICY_NAME"
            cs_falcon_sensor_version_dec=0
        fi
    fi

    existing_installers=$(
        target_curl_command -G "https://$(target_cs_cloud)/sensors/combined/installers/v2?sort=version|desc" \
            --data-urlencode "filter=os:\"$cs_os_name\"+os_version:\"*$cs_os_version*\"$cs_api_version_filter$cs_os_arch_filter"
    )

    handle_curl_error $?

    if echo "$existing_installers" | grep "authorization failed"; then
        die "Access denied: Please make sure that your target Falcon API credentials allow sensor download (scope Sensor Download [read])"
    elif echo "$existing_installers" | grep "invalid bearer token"; then
        die "Invalid Access Token: $target_cs_falcon_oauth_token"
    fi

    sha_list=$(echo "$existing_installers" | json_value "sha256")
    if [ -z "$sha_list" ]; then
        die "No sensor found for OS: $cs_os_name, Version: $cs_os_version. Either the OS or the OS version is not yet supported."
    fi

    # Set the index accordingly (the json_value expects and index+1 value)
    INDEX=$((cs_falcon_sensor_version_dec + 1))

    sha=$(echo "$existing_installers" | json_value "sha256" "$INDEX" |
        sed 's/ *$//g' | sed 's/^ *//g')
    if [ -z "$sha" ]; then
        die "Unable to identify a sensor installer matching: $cs_os_name, version: $cs_os_version, index: N-$cs_falcon_sensor_version_dec"
    fi
    file_type=$(echo "$existing_installers" | json_value "file_type" "$INDEX" | sed 's/ *$//g' | sed 's/^ *//g')

    installer="${destination_dir}/falcon-sensor.${file_type}"

    target_curl_command "https://$(target_cs_cloud)/sensors/entities/download-installer/v1?id=$sha" -o "${installer}"

    handle_curl_error $?

    echo "$installer"
}

# Get sensor version from policy
cs_sensor_policy_version() {
    local cs_policy_name="$1" sensor_update_policy sensor_update_versions

    sensor_update_policy=$(
        target_curl_command -G "https://$(target_cs_cloud)/policy/combined/sensor-update/v2" \
            --data-urlencode "filter=platform_name:\"Linux\"+name.raw:\"$cs_policy_name\""
    )

    handle_curl_error $?

    if echo "$sensor_update_policy" | grep "authorization failed"; then
        die "Access denied: Please make sure that your target Falcon API credentials allow access to sensor update policies (scope Sensor update policies [read])"
    elif echo "$sensor_update_policy" | grep "invalid bearer token"; then
        die "Invalid Access Token: $target_cs_falcon_oauth_token"
    fi

    sensor_update_versions=$(echo "$sensor_update_policy" | json_value "sensor_version")
    if [ -z "$sensor_update_versions" ]; then
        die "Could not find a sensor update policy with name: $cs_policy_name"
    fi

    oldIFS=$IFS
    IFS=" "
    # shellcheck disable=SC2086
    set -- $sensor_update_versions
    if [ "$(echo "$sensor_update_versions" | wc -w)" -gt 1 ]; then
        if [ "$cs_os_arch" = "aarch64" ]; then
            echo "$2"
        else
            echo "$1"
        fi
    else
        echo "$1"
    fi
    IFS=$oldIFS
}

# Install package based on OS
os_install_package() {
    local pkg="$1"
    # Check for package manager lock prior to installation
    check_package_manager_lock

    rpm_install_package() {
        local pkg="$1"

        cs_falcon_gpg_import

        if type dnf >/dev/null 2>&1; then
            dnf install -q -y "$pkg" || rpm -ivh --nodeps "$pkg"
        elif type yum >/dev/null 2>&1; then
            yum install -q -y "$pkg" || rpm -ivh --nodeps "$pkg"
        elif type zypper >/dev/null 2>&1; then
            zypper --quiet install -y "$pkg" || rpm -ivh --nodeps "$pkg"
        else
            rpm -ivh --nodeps "$pkg"
        fi
    }
    # shellcheck disable=SC2221,SC2222
    case "${os_name}" in
        Amazon | CentOS* | Oracle | RHEL | Rocky | AlmaLinux | SLES)
            rpm_install_package "$pkg"
            ;;
        Debian)
            DEBIAN_FRONTEND=noninteractive apt-get -qq install -y "$pkg" >/dev/null
            ;;
        Ubuntu)
            # If this is ubuntu 14, we need to use dpkg instead
            if [ "${cs_os_version}" -eq 14 ]; then
                DEBIAN_FRONTEND=noninteractive dpkg -i "$pkg" >/dev/null 2>&1 || true
                DEBIAN_FRONTEND=noninteractive apt-get -qq install -f -y >/dev/null
            else
                DEBIAN_FRONTEND=noninteractive apt-get -qq install -y "$pkg" >/dev/null
            fi
            ;;
        *)
            die "Unrecognized OS: ${os_name}"
            ;;
    esac
}

# Import GPG key for RPM packages
cs_falcon_gpg_import() {
    tempfile=$(mktemp)
    cat >"$tempfile" <<EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
0k88iw==
=X91W
-----END PGP PUBLIC KEY BLOCK-----
EOF
    rpm --import "$tempfile"
    rm "$tempfile"
}

# Register the sensor
register_sensor() {
    # Get the falcon cid if not already set
    if [ -z "$new_cid" ]; then
        new_cid=$(get_new_falcon_cid)
    fi

    # If cs_falcon_token is not set, try getting it from api
    if [ -z "$FALCON_PROVISIONING_TOKEN" ] && [ -n "$new_provisioning_token" ]; then
        FALCON_PROVISIONING_TOKEN="$new_provisioning_token"
    fi

    # Assemble the registration arguments
    # add the cid to the params
    cs_falcon_args=--cid="${new_cid}"
    if [ -n "${FALCON_PROVISIONING_TOKEN}" ]; then
        cs_token=--provisioning-token="${FALCON_PROVISIONING_TOKEN}"
        cs_falcon_args="$cs_falcon_args $cs_token"
    fi

    # add tags to the params
    if [ -n "${FALCON_TAGS}" ]; then
        cs_falconctl_opt_tags=--tags="$FALCON_TAGS"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_tags"
    fi

    # add proxy enable/disable param
    if [ -n "${FALCON_APD}" ]; then
        cs_falconctl_opt_apd=--apd=$FALCON_APD
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_apd"
    fi

    # add proxy host to the params
    if [ -n "${FALCON_APH}" ]; then
        cs_falconctl_opt_aph=--aph="${FALCON_APH}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_aph"
    fi

    # add proxy port to the params
    if [ -n "${FALCON_APP}" ]; then
        cs_falconctl_opt_app=--app="${FALCON_APP}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_app"
    fi

    # add the billing type to the params
    if [ -n "${FALCON_BILLING}" ]; then
        cs_falconctl_opt_billing=--billing="${FALCON_BILLING}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_billing"
    fi

    # add the backend to the params
    if [ -n "${FALCON_BACKEND}" ]; then
        cs_falconctl_opt_backend=--backend="${FALCON_BACKEND}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_backend"
    fi

    # add the trace level to the params
    if [ -n "${FALCON_TRACE}" ]; then
        cs_falconctl_opt_trace=--trace="${FALCON_TRACE}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_trace"
    fi

    echo "Registering sensor with new CID: $new_cid"
    if [ -n "$FALCON_TAGS" ]; then
        echo "Applying tags: $FALCON_TAGS"
    fi

    # run the configuration command
    # shellcheck disable=SC2086
    /opt/CrowdStrike/falconctl -s -f ${cs_falcon_args} >/dev/null
}

# Restart the sensor
restart_sensor() {
    if type systemctl >/dev/null 2>&1; then
        systemctl restart falcon-sensor
    elif type service >/dev/null 2>&1; then
        service falcon-sensor restart
    else
        die "Could not restart falcon sensor"
    fi
}

# Setup AWS SSM Parameter retrieval if needed
aws_ssm_parameter() {
    local param_name="$1"

    hmac_sha256() {
        key="$1"
        data="$2"
        echo -n "$data" | openssl dgst -sha256 -mac HMAC -macopt "$key" | sed 's/^.* //'
    }

    token=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
    api_endpoint="AmazonSSM.GetParameters"
    iam_role="$(curl -s -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/iam/security-credentials/)"
    aws_my_region="$(curl -s -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/placement/availability-zone | sed s/.$//)"
    _security_credentials="$(curl -s -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/iam/security-credentials/"$iam_role")"
    access_key_id="$(echo "$_security_credentials" | grep AccessKeyId | sed -e 's/  "AccessKeyId" : "//' -e 's/",$//')"
    access_key_secret="$(echo "$_security_credentials" | grep SecretAccessKey | sed -e 's/  "SecretAccessKey" : "//' -e 's/",$//')"
    security_token="$(echo "$_security_credentials" | grep Token | sed -e 's/  "Token" : "//' -e 's/",$//')"
    datetime=$(date -u +"%Y%m%dT%H%M%SZ")
    date=$(date -u +"%Y%m%d")
    request_data='{"Names":["'"${param_name}"'"],"WithDecryption":"true"}'
    request_data_dgst=$(echo -n "$request_data" | openssl dgst -sha256 | awk -F' ' '{print $2}')
    request_dgst=$(
        cat <<EOF | head -c -1 | openssl dgst -sha256 | awk -F' ' '{print $2}'
POST
/

content-type:application/x-amz-json-1.1
host:ssm.$aws_my_region.amazonaws.com
x-amz-date:$datetime
x-amz-security-token:$security_token
x-amz-target:$api_endpoint

content-type;host;x-amz-date;x-amz-security-token;x-amz-target
$request_data_dgst
EOF
    )
    dateKey=$(hmac_sha256 key:"AWS4$access_key_secret" "$date")
    dateRegionKey=$(hmac_sha256 "hexkey:$dateKey" "$aws_my_region")
    dateRegionServiceKey=$(hmac_sha256 "hexkey:$dateRegionKey" ssm)
    hex_key=$(hmac_sha256 "hexkey:$dateRegionServiceKey" "aws4_request")

    signature=$(
        cat <<EOF | head -c -1 | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$hex_key" | awk -F' ' '{print $2}'
AWS4-HMAC-SHA256
$datetime
$date/$aws_my_region/ssm/aws4_request
$request_dgst
EOF
    )

    response=$(
        curl -s "https://ssm.$aws_my_region.amazonaws.com/" \
            -x "$proxy" \
            -H "Authorization: AWS4-HMAC-SHA256 \
            Credential=$access_key_id/$date/$aws_my_region/ssm/aws4_request, \
            SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, \
            Signature=$signature" \
            -H "x-amz-security-token: $security_token" \
            -H "x-amz-target: $api_endpoint" \
            -H "content-type: application/x-amz-json-1.1" \
            -d "$request_data" \
            -H "x-amz-date: $datetime"
    )
    handle_curl_error $?
    if ! echo "$response" | grep -q '^.*"InvalidParameters":\[\].*$'; then
        die "Unexpected response from AWS SSM Parameter Store: $response"
    elif ! echo "$response" | grep -q '^.*'"${param_name}"'.*$'; then
        die "Unexpected response from AWS SSM Parameter Store: $response"
    fi
    echo "$response"
}

# Enable strict mode
set -e
