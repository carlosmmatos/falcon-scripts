#!/bin/bash
#
# Bash script to migrate Falcon sensor to another falcon CID.
#

VERSION="1.7.4"

print_usage() {
    cat <<EOF

Usage: $0 [-h|--help]

Migrates the Falcon sensor to another Falcon CID.
Version: $VERSION

This script recognizes the following environmental variables:

Old CID Authentication:
    - OLD_FALCON_CLIENT_ID              (default: unset) [Required]
        Your CrowdStrike Falcon API client ID for the old CID.

    - OLD_FALCON_CLIENT_SECRET          (default: unset) [Required]
        Your CrowdStrike Falcon API client secret for the old CID.

    - OLD_FALCON_MEMBER_CID              (default: unset)
        Member CID, used only in multi-CID ("Falcon Flight Control") configurations and
        with a parent management CID for the old CID.

    - OLD_FALCON_CLOUD                  (default: 'us-1')
        The cloud region where your old CrowdStrike Falcon instance is hosted.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1'].

New CID Authentication:
    - NEW_FALCON_CLIENT_ID              (default: unset) [Required]
        Your CrowdStrike Falcon API client ID for the new CID.

    - NEW_FALCON_CLIENT_SECRET          (default: unset) [Required]
        Your CrowdStrike Falcon API client secret for the new CID.

    - NEW_FALCON_MEMBER_CID              (default: unset)
        Member CID, used only in multi-CID ("Falcon Flight Control") configurations and
        with a parent management CID for the new CID.

    - NEW_FALCON_CLOUD                  (default: 'us-1')
        The cloud region where your new CrowdStrike Falcon instance is hosted.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1'].

    - NEW_FALCON_CID                    (default: unset)
        Your CrowdStrike Falcon customer ID (CID) for the new CID.
        If not specified, will be detected automatically via API.

Migration Options:
    - MIGRATE_TAGS                      (default: true)
        Migrate the host's existing tags to the target CID.
        Accepted values are ['true', 'false'].

    - LOG_PATH                          (default: /tmp)
        Location of the log and recovery files.

Other Options
    - FALCON_MAINTENANCE_TOKEN          (default: unset)
        Sensor uninstall maintenance token used to unlock sensor uninstallation.
        If not provided the script will try to retrieve the token from the API.

    - FALCON_PROVISIONING_TOKEN         (default: unset)
        The provisioning token to use for installing the sensor.
        If the provisioning token is unset, the script will attempt to retrieve it from
        the API using your authentication credentials and token requirements.

    - FALCON_REMOVE_HOST                (default: unset)
        Determines whether the host should be removed from the Falcon console after uninstalling the sensor.
        Requires API Authentication.
        NOTE: It is recommended to use Host Retention Policies in the Falcon console instead.
        Accepted values are ['true', 'false'].

    - FALCON_SENSOR_VERSION_DECREMENT   (default: 0 [latest])
        The number of versions prior to the latest release to install.
        For example, 1 would install version N-1.

    - FALCON_SENSOR_UPDATE_POLICY_NAME  (default: unset)
        The name of the sensor update policy to use for installing the sensor.

    - FALCON_TAGS                       (default: unset)
        A comma-separated list of sensor grouping tags to apply to the host in addition
        to any pre-existing tags.

    - FALCON_GROUPING_TAGS              (default: unset)
        A comma-separated list of Falcon grouping tags to apply to the host in addition
        to any pre-existing Falcon grouping tags.

    - FALCON_APD                        (default: unset)
        Configures if the proxy should be enabled or disabled.

    - FALCON_APH                        (default: unset)
        The proxy host for the sensor to use when communicating with CrowdStrike.

    - FALCON_APP                        (default: unset)
        The proxy port for the sensor to use when communicating with CrowdStrike.

    - FALCON_BILLING                    (default: default)
        To configure the sensor billing type.
        Accepted values are [default|metered].

    - FALCON_BACKEND                    (default: auto)
        For sensor backend.
        Accepted values are values: [auto|bpf|kernel].

    - FALCON_TRACE                      (default: none)
        To configure the trace level.
        Accepted values are [none|err|warn|info|debug]

    - ALLOW_LEGACY_CURL                 (default: false)
        To use the legacy version of curl; version < 7.55.0.

    - USER_AGENT                        (default: unset)
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

# Ensure script is ran as root/sudo
if [ "$(id -u)" -ne 0 ]; then
    die "This script must be ran as root or with sudo."
fi

# Error handling function
die() {
    echo "ERROR: $*" >&2
    exit 1
}

json_value() {
    KEY=$1
    num=$2
    awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'"$KEY"'\042/){print $(i+1)}}}' | tr -d '"' | sed -n "${num}p"
}

# set variables
old_cs_falcon_cloud="${OLD_FALCON_CLOUD:-us-1}"
new_cs_falcon_cloud="${NEW_FALCON_CLOUD:-us-1}"
migrate_tags="${MIGRATE_TAGS:-true}"

# Use the system's temporary directory
log_path="${LOG_PATH:-/tmp}"
recovery_file="$log_path/falcon_migration_recovery.json"
log_file="$log_path/falcon_migration_$(date +%Y%m%d_%H%M%S).log"

# Create log file
touch "$log_file"
echo "Migration started at $(date)" >> "$log_file"

log() {
    local level="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" | tee -a "$log_file"
}

# Check if curl is installed
if ! command -v curl >/dev/null 2>&1; then
    die "The 'curl' command is missing. Please install it before continuing."
fi

# Check if curl is greater or equal to 7.55
check_curl_version() {
    local version minimum old_curl
    version=$(curl --version | head -n 1 | awk '{ print $2 }')
    minimum="7.55"

    # Check if the version is less than the minimum
    if printf "%s\n" "$version" "$minimum" | sort -V -C; then
        old_curl=0
    else
        old_curl=1
    fi

    # Old curl print warning message
    if [ "$old_curl" -eq 0 ]; then
        if [ "${ALLOW_LEGACY_CURL}" != "true" ]; then
            cat <<EOF

WARNING: Your version of curl does not support the ability to pass headers via stdin.
For security considerations, we strongly recommend upgrading to curl 7.55.0 or newer.

To bypass this warning, set the environment variable ALLOW_LEGACY_CURL=true
EOF
            exit 1
        fi
    fi

    echo "$old_curl"
}

old_curl=$(check_curl_version)

# Function to validate cloud region
validate_cloud_region() {
    local cloud_region="$1"
    case "${cloud_region}" in
        us-1 | us-2 | eu-1 | us-gov-1) ;;
        *) die "Unrecognized Falcon Cloud: ${cloud_region}" ;;
    esac
}

# Get the Falcon cloud API endpoint
cs_cloud() {
    local cloud="$1"
    case "${cloud}" in
        us-1) echo "api.crowdstrike.com" ;;
        us-2) echo "api.us-2.crowdstrike.com" ;;
        eu-1) echo "api.eu-1.crowdstrike.com" ;;
        us-gov-1) echo "api.laggar.gcw.crowdstrike.com" ;;
        *) die "Unrecognized Falcon Cloud: ${cloud}" ;;
    esac
}

# Validate cloud regions
validate_cloud_region "$old_cs_falcon_cloud"
validate_cloud_region "$new_cs_falcon_cloud"

# Handle error codes returned by curl
handle_curl_error() {
    local err_msg

    # Failed to download the file to destination
    if [ "$1" -eq 23 ]; then
        err_msg="Failed writing received data to disk/destination (exit code 23). Please check the destination path and permissions."
        die "$err_msg"
    fi

    # Proxy related errors
    if [ "$1" = "28" ]; then
        err_msg="Operation timed out (exit code 28)."
        if [ -n "$proxy" ]; then
            err_msg="$err_msg A proxy was used to communicate ($proxy). Please check your proxy settings."
        fi
        die "$err_msg"
    fi

    if [ "$1" = "5" ]; then
        err_msg="Couldn't resolve proxy (exit code 5). The address ($proxy) of the given proxy host could not be resolved. Please check your proxy settings."
        die "$err_msg"
    fi

    if [ "$1" = "7" ]; then
        err_msg="Failed to connect to host (exit code 7). Host found, but unable to open connection with host."
        if [ -n "$proxy" ]; then
            err_msg="$err_msg A proxy was used to communicate ($proxy). Please check your proxy settings."
        fi
        die "$err_msg"
    fi
}

curl_command() {
    # Dash does not support arrays, so we have to pass the args as separate arguments
    set -- "$@"

    if [ "$old_curl" -eq 0 ]; then
        curl -s -x "$proxy" -L -H "Authorization: Bearer ${cs_falcon_oauth_token}" "$@"
    else
        echo "Authorization: Bearer ${cs_falcon_oauth_token}" | curl -s -x "$proxy" -L -H @- "$@"
    fi
}

get_user_agent() {
    local user_agent="crowdstrike-falcon-scripts/$VERSION"
    if [ -n "$USER_AGENT" ]; then
        user_agent="${user_agent} ${USER_AGENT}"
    fi
    echo "$user_agent"
}

# Get the Falcon OAuth token
get_oauth_token() {
    local client_id="$1"
    local client_secret="$2"
    local cloud="$3"
    local response_headers

    if [ -z "$client_id" ] || [ -z "$client_secret" ]; then
        die "Client ID and Client Secret are required for authentication."
    fi

    response_headers=$(mktemp)

    local token_result token
    token_result=$(echo "client_id=$client_id&client_secret=$client_secret" |
        curl -X POST -s -x "$proxy" -L "https://$(cs_cloud "$cloud")/oauth2/token" \
            -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
            -H "User-Agent: $(get_user_agent)" \
            --dump-header "${response_headers}" \
            --data @-)

    handle_curl_error $?

    token=$(echo "$token_result" | json_value "access_token" | sed 's/ *$//g' | sed 's/^ *//g')
    if [ -z "$token" ]; then
        die "Unable to obtain CrowdStrike Falcon OAuth Token. Double check your credentials and/or ensure you set the correct cloud region."
    fi

    region_hint=$(grep -i ^x-cs-region: "$response_headers" | head -n 1 | tr '[:upper:]' '[:lower:]' | tr -d '\r' | sed 's/^x-cs-region: //g')

    if [ -z "${cloud}" ]; then
        if [ -z "${region_hint}" ]; then
            die "Unable to obtain region hint from CrowdStrike Falcon OAuth API, Please provide OLD|NEW_FALCON_CLOUD environment variable as an override."
        fi
        cloud="${region_hint}"
    else
        if [ "x${cloud}" != "x${region_hint}" ]; then
            log "WARNING" "OLD|NEW_FALCON_CLOUD='${cloud}' environment variable specified while credentials only exists in '${region_hint}'" >&2
        fi
    fi

    rm "${response_headers}"
    echo "$token"
}

get_provisioning_token() {
    local cloud="$1"
    local check_settings is_required token_value
    # First, let's check if installation tokens are required
    check_settings=$(curl_command "https://$(cs_cloud "$cloud")/installation-tokens/entities/customer-settings/v1")
    handle_curl_error $?

    if echo "$check_settings" | grep "authorization failed" >/dev/null; then
        # For now we just return. We can error out once more people get a chance to update their API keys
        return
    fi

    is_required=$(echo "$check_settings" | json_value "tokens_required" | xargs)
    if [ "$is_required" = "true" ]; then
        local token_query token_id token_result
        # Get the token ID
        token_query=$(curl_command "https://$(cs_cloud "$cloud")/installation-tokens/queries/tokens/v1")
        token_id=$(echo "$token_query" | tr -d '\n" ' | awk -F'[][]' '{print $2}' | cut -d',' -f1)
        if [ -z "$token_id" ]; then
            die "No installation token found in a required token environment."
        fi

        # Get the token value from ID
        token_result=$(curl_command "https://$(cs_cloud "$cloud")/installation-tokens/entities/tokens/v1?ids=$token_id")
        token_value=$(echo "$token_result" | json_value "value" | xargs)
        if [ -z "$token_value" ]; then
            die "Could not obtain installation token value."
        fi
    fi

    echo "$token_value"
}

get_falcon_cid() {
    local cloud="$1"
    local
    if [ -n "$NEW_FALCON_CID" ]; then
        echo "$NEW_FALCON_CID"
    else
        cs_target_cid=$(curl_command "https://$(cs_cloud "$cloud")/sensors/queries/installers/ccid/v1")

        handle_curl_error $?

        if [ -z "$cs_target_cid" ]; then
            die "Unable to obtain CrowdStrike Falcon CID. Response was $cs_target_cid"
        fi
        echo "$cs_target_cid" | tr -d '\n" ' | awk -F'[][]' '{print $2}'
    fi
}

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

cs_sensor_remove() {
    local cs_maintenance_token="$1"
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

    # Handle maintenance protection
    if [ -n "$cs_maintenance_token" ]; then
        # shellcheck disable=SC2086
        if ! /opt/CrowdStrike/falconctl -s -f --maintenance-token=${cs_maintenance_token} >/dev/null 2>&1; then
            die "Failed to apply maintenance token. Uninstallation may fail."
        fi
    fi

    # Check for package manager lock prior to uninstallation
    check_package_manager_lock

    remove_package "falcon-sensor"
}

cs_remove_host_from_console() {
    local aid="$1"
    local cloud="$2"

    if [ -z "$aid" ]; then
        log "WARNING" 'Unable to find AID. Skipping host removal from console.'
    else
        payload="{\"ids\": [\"$aid\"]}"
        url="https://$(cs_cloud "$cloud")/devices/entities/devices-actions/v2?action_name=hide_host"

        curl_command -X "POST" -H "Content-Type: application/json" -d "$payload" "$url" >/dev/null

        handle_curl_error $?
    fi
}

get_aid() {
    aid="$(/opt/CrowdStrike/falconctl -g --aid | awk -F '"' '{print $2}')"
}

cs_sensor_installed() {
    if ! test -f /opt/CrowdStrike/falconctl; then
        log "WARNING" "Falcon sensor is already uninstalled." && exit 0
    fi
    # Get AID if FALCON_REMOVE_HOST is set to true or if we need to get a maintenance token
    if [ "${FALCON_REMOVE_HOST}" = "true" ] || [ -n "$FALCON_CLIENT_ID" ] && [ -n "$FALCON_CLIENT_SECRET" ] && [ -z "$FALCON_MAINTENANCE_TOKEN" ]; then
        get_aid
    fi
}

cs_sensor_is_running() {
    if pgrep -u root falcon-sensor >/dev/null 2>&1; then
        log "WARNING" "sensor is already running... exiting"
        exit 0
    fi
}

cs_sensor_restart() {
    if type systemctl >/dev/null 2>&1; then
        systemctl restart falcon-sensor
    elif type service >/dev/null 2>&1; then
        service falcon-sensor restart
    else
        die "Could not restart falcon sensor"
    fi
}

cs_sensor_install() {
    local tempdir package_name
    tempdir=$(mktemp -d)

    tempdir_cleanup() { rm -rf "$tempdir"; }
    trap tempdir_cleanup EXIT

    package_name=$(cs_sensor_download "$tempdir")
    os_install_package "$package_name"

    tempdir_cleanup
}

os_install_package() {
    local pkg="$1"
    # Check for package manager lock prior to uninstallation
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

cs_sensor_policy_version() {
    local cs_policy_name="$1" sensor_update_policy sensor_update_versions

    sensor_update_policy=$(
        curl_command -G "https://$(cs_cloud)/policy/combined/sensor-update/v2" \
            --data-urlencode "filter=platform_name:\"Linux\"+name.raw:\"$cs_policy_name\""
    )

    handle_curl_error $?

    if echo "$sensor_update_policy" | grep "authorization failed"; then
        die "Access denied: Please make sure that your Falcon API credentials allow access to sensor update policies (scope Sensor update policies [read])"
    elif echo "$sensor_update_policy" | grep "invalid bearer token"; then
        die "Invalid Access Token: $cs_falcon_oauth_token"
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

cs_sensor_download() {
    local destination_dir="$1" existing_installers sha_list INDEX sha file_type installer

    if [ -n "$cs_sensor_policy_name" ]; then
        cs_sensor_version=$(cs_sensor_policy_version "$cs_sensor_policy_name")
        cs_api_version_filter="+version:\"$cs_sensor_version\""

        if [ "$cs_falcon_sensor_version_dec" -gt 0 ]; then
            echo "WARNING: Disabling FALCON_SENSOR_VERSION_DECREMENT because it conflicts with FALCON_SENSOR_UPDATE_POLICY_NAME"
            cs_falcon_sensor_version_dec=0
        fi
    fi

    existing_installers=$(
        curl_command -G "https://$(cs_cloud)/sensors/combined/installers/v2?sort=version|desc" \
            --data-urlencode "filter=os:\"$cs_os_name\"+os_version:\"*$cs_os_version*\"$cs_api_version_filter$cs_os_arch_filter"
    )

    handle_curl_error $?

    if echo "$existing_installers" | grep "authorization failed"; then
        die "Access denied: Please make sure that your Falcon API credentials allow sensor download (scope Sensor Download [read])"
    elif echo "$existing_installers" | grep "invalid bearer token"; then
        die "Invalid Access Token: $cs_falcon_oauth_token"
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

    curl_command "https://$(cs_cloud)/sensors/entities/download-installer/v1?id=$sha" -o "${installer}"

    handle_curl_error $?

    echo "$installer"
}

get_maintenance_token() {
    local aid="$1"
    local cloud="$2"
    local cs_maintenance_token

    if [ -z "$aid" ]; then
        die "Unable to find AID. Cannot retrieve maintenance token."
    fi

    log "INFO" "Retrieving maintenance token from the CrowdStrike Falcon API..."

    payload="{\"device_id\": \"$aid\", \"audit_message\": \"CrowdStrike Falcon Uninstall Bash Script\"}"
    url="https://$(cs_cloud "$cloud")/policy/combined/reveal-uninstall-token/v1"

    response=$(curl_command -X "POST" -H "Content-Type: application/json" -d "$payload" "$url")

    handle_curl_error $?

    if echo "$response" | grep -q "\"uninstall_token\""; then
        cs_maintenance_token=$(echo "$response" | json_value "uninstall_token" 1 | sed 's/ *$//g' | sed 's/^ *//g')
        if [ -z "$cs_maintenance_token" ]; then
            die "Retrieved empty maintenance token from API."
        fi
    else
        die "Failed to retrieve maintenance token. Response: $response"
    fi

    echo "$cs_maintenance_token"
}

cs_sensor_register() {
    local cloud="$1"
    # Get the falcon cid
    cs_falcon_cid="$(get_falcon_cid "$cloud")"
    # If cs_falcon_token is not set, try getting it from api
    if [ -z "${cs_falcon_token}" ]; then
        cs_falcon_token="$(get_provisioning_token "$cloud")"
    fi
    # add the cid to the params
    cs_falcon_args=--cid="${cs_falcon_cid}"
    if [ -n "${cs_falcon_token}" ]; then
        cs_token=--provisioning-token="${cs_falcon_token}"
        cs_falcon_args="$cs_falcon_args $cs_token"
    fi
    # add tags to the params
    if [ -n "${FALCON_TAGS}" ]; then
        cs_falconctl_opt_tags=--tags="$FALCON_TAGS"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_tags"
    fi
    # add proxy enable/disable param
    if [ -n "${cs_falcon_apd}" ]; then
        cs_falconctl_opt_apd=--apd=$cs_falcon_apd
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
        cs_falconctl_opt_billing=--billing="${cs_falcon_billing}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_billing"
    fi
    # add the backend to the params
    if [ -n "${cs_falcon_backend}" ]; then
        cs_falconctl_opt_backend=--backend="${cs_falcon_backend}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_backend"
    fi
    # add the trace level to the params
    if [ -n "${cs_falcon_trace}" ]; then
        cs_falconctl_opt_trace=--trace="${cs_falcon_trace}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_trace"
    fi
    # run the configuration command
    # shellcheck disable=SC2086
    /opt/CrowdStrike/falconctl -s -f ${cs_falcon_args} >/dev/null
}

# Create a recovery file to track tags and AID in case migration fails
create_recovery_file() {
    local sensor_tags="$1"
    local falcon_tags="$2"
    local old_aid="$3"
    local path="$4"

    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$path")"

    # Write data to recovery file in simple CSV format
    echo "OldAid,SensorTags,FalconTags" > "$path"
    echo "$old_aid,$sensor_tags,$falcon_tags" >> "$path"

    log "INFO" "Recovery file created at $path"
}

# Read data from recovery file
read_recovery_file() {
    local path="$1"

    if [ ! -f "$path" ]; then
        log "WARNING" "Recovery file not found at $path"
        return 1
    fi

    # Skip header line and read data
    old_aid=$(tail -n 1 "$path" | cut -d ',' -f 1)
    sensor_tags=$(tail -n 1 "$path" | cut -d ',' -f 2)
    falcon_tags=$(tail -n 1 "$path" | cut -d ',' -f 3)

    log "INFO" "Recovery data loaded: AID=$old_aid"
    return 0
}

# Get the host's tags from a specific Falcon instance
get_falcon_tags() {
    local base_url="$1"
    local headers="$2"
    local aid="$3"

    log "INFO" "Retrieving tags for host with AID: $aid"

    local response
    response=$(curl_command "https://$base_url/devices/entities/devices/v2?ids=$aid")

    handle_curl_error $?

    if echo "$response" | grep "authorization failed" >/dev/null; then
        die "Access denied: Please make sure your Falcon API credentials allow access to host data (scope Host [read])"
    elif echo "$response" | grep "invalid bearer token" >/dev/null; then
        die "Invalid Access Token: $token"
    fi

    # Extract tags from response
    local tags
    tags=$(echo "$response" | grep -o '"tags":\[[^]]*\]' | sed 's/"tags":\[//;s/\]//')

    # Strip quotes
    tags=$(echo "$tags" | tr -d '"' | tr ',' ' ')

    echo "$tags"
}

# Split tags into sensor tags and falcon tags
split_tags() {
    local tags="$1"
    local sensor_tags=""
    local falcon_tags=""
    local tag=""

    # Create a temporary file with one tag per line
    local tmpfile
    tmpfile=$(mktemp)
    echo "$tags" | tr ' ' '\n' > "$tmpfile"

    while read -r tag; do
        case "$tag" in
            SensorGroupingTags/*)
                # Extract the tag part after SensorGroupingTags/
                local sensor_tag
                sensor_tag=$(echo "$tag" | sed 's/^SensorGroupingTags\///')
                if [ -n "$sensor_tags" ]; then
                    sensor_tags="$sensor_tags,$sensor_tag"
                else
                    sensor_tags="$sensor_tag"
                fi
                ;;
            FalconGroupingTags/*)
                # Extract the tag part after FalconGroupingTags/
                local falcon_tag
                falcon_tag=$(echo "$tag" | sed 's/^FalconGroupingTags\///')
                if [ -n "$falcon_tags" ]; then
                    falcon_tags="$falcon_tags,$falcon_tag"
                else
                    falcon_tags="$falcon_tag"
                fi
                ;;
        esac
    done < "$tmpfile"

    rm -f "$tmpfile"

    echo "$sensor_tags;$falcon_tags"
}

# Set tags for a host in a Falcon instance
set_falcon_tags() {
    local base_url="$1"
    local headers="$2"
    local aid="$3"
    local tags="$4"

    log "INFO" "Setting tags for host with AID: $aid"

    # Prepare the tags payload
    local payload
    payload=$(cat <<EOF
{
    "action": "append",
    "device_ids": ["$aid"],
    "tags": [$tags]
}
EOF
    )

    local response
    response=$(curl_command -X "PATCH" -H "Content-Type: application/json" -d "$payload" "https://$base_url/devices/entities/devices/tags/v1")

    handle_curl_error $?

    if echo "$response" | grep "authorization failed" >/dev/null; then
        die "Access denied: Please make sure your Falcon API credentials allow access to host data (scope Host [write])"
    elif echo "$response" | grep "invalid bearer token" >/dev/null; then
        die "Invalid Access Token: $token"
    elif echo "$response" | grep "\"updated\":true" >/dev/null; then
        log "INFO" "Successfully set tags on host"
        return 0
    else
        log "WARNING" "Failed to set tags: $response"
        return 1
    fi
}

# Format tags for API request
format_tags_for_api() {
    local tags="$1"
    local prefix="$2"  # e.g., "FalconGroupingTags" or "SensorGroupingTags"
    local formatted_tags=""

    # Create a temp file with one tag per line
    local tmpfile
    tmpfile=$(mktemp)
    echo "$tags" | tr ',' '\n' > "$tmpfile"

    while read -r tag; do
        # Skip empty tags
        if [ -n "$tag" ]; then
            if [ -n "$formatted_tags" ]; then
                formatted_tags="$formatted_tags,\"$prefix/$tag\""
            else
                formatted_tags="\"$prefix/$tag\""
            fi
        fi
    done < "$tmpfile"

    rm -f "$tmpfile"
    echo "$formatted_tags"
}

# Merge tags with new tags, removing duplicates
merge_tags() {
    local existing_tags="$1"
    local new_tags="$2"
    local merged_tags="$existing_tags"

    # Create a temp file with one tag per line from new_tags
    local tmpfile
    tmpfile=$(mktemp)
    echo "$new_tags" | tr ',' '\n' > "$tmpfile"

    while read -r tag; do
        # Skip empty tags
        if [ -n "$tag" ]; then
            # Check if tag exists in merged_tags
            if ! echo ",$merged_tags," | grep -q ",$tag,"; then
                if [ -n "$merged_tags" ]; then
                    merged_tags="$merged_tags,$tag"
                else
                    merged_tags="$tag"
                fi
            fi
        fi
    done < "$tmpfile"

    rm -f "$tmpfile"
    echo "$merged_tags"
}

set -e

os_name=$(
    # returns either: Amazon, Ubuntu, CentOS, RHEL, or SLES
    # lsb_release is not always present
    name=$(cat /etc/*release | grep ^NAME= | awk -F'=' '{ print $2 }' | sed "s/\"//g;s/Red Hat.*/RHEL/g;s/ Linux$//g;s/ GNU\/Linux$//g;s/Oracle.*/Oracle/g;s/Amazon.*/Amazon/g")
    if [ -z "$name" ]; then
        if lsb_release -s -i | grep -q ^RedHat; then
            name="RHEL"
        elif [ -f /usr/bin/lsb_release ]; then
            name=$(/usr/bin/lsb_release -s -i)
        fi
    fi
    if [ -z "$name" ]; then
        die "Cannot recognise operating system"
    fi

    echo "$name"
)

os_version=$(
    version=$(cat /etc/*release | grep VERSION_ID= | awk '{ print $1 }' | awk -F'=' '{ print $2 }' | sed "s/\"//g")
    if [ -z "$version" ]; then
        if type rpm >/dev/null 2>&1; then
            # older systems may have *release files of different form
            version=$(rpm -qf /etc/redhat-release --queryformat '%{VERSION}' | sed 's/\([[:digit:]]\+\).*/\1/g')
        elif [ -f /etc/debian_version ]; then
            version=$(cat /etc/debian_version)
        elif [ -f /usr/bin/lsb_release ]; then
            version=$(/usr/bin/lsb_release -r | /usr/bin/cut -f 2-)
        fi
    fi
    if [ -z "$version" ]; then
        cat /etc/*release >&2
        die "Could not determine distribution version"
    fi
    echo "$version"
)

cs_os_name=$(
    # returns OS name as recognised by CrowdStrike Falcon API
    # shellcheck disable=SC2221,SC2222
    case "${os_name}" in
        Amazon)
            echo "Amazon Linux"
            ;;
        CentOS* | Oracle | RHEL | Rocky | AlmaLinux)
            echo "*RHEL*"
            ;;
        Debian)
            echo "Debian"
            ;;
        SLES)
            echo "SLES"
            ;;
        Ubuntu)
            echo "Ubuntu"
            ;;
        *)
            die "Unrecognized OS: ${os_name}"
            ;;
    esac
)

cs_os_arch=$(
    uname -m
)

cs_os_arch_filter=$(
    case "${cs_os_arch}" in
        x86_64)
            echo "+architectures:\"x86_64\""
            ;;
        aarch64)
            echo "+architectures:\"arm64\""
            ;;
        s390x)
            echo "+architectures:\"s390x\""
            ;;
        *)
            die "Unrecognized OS architecture: ${cs_os_arch}"
            ;;
    esac
)

cs_os_version=$(
    version=$(echo "$os_version" | awk -F'.' '{print $1}')
    # Check if we are using Amazon Linux 1
    if [ "${os_name}" = "Amazon" ]; then
        if [ "$version" != "2" ] && [ "$version" -le 2018 ]; then
            version="1"
        fi
    fi
    echo "$version"
)

cs_falcon_token=$(
    if [ -n "$FALCON_PROVISIONING_TOKEN" ]; then
        echo "$FALCON_PROVISIONING_TOKEN"
    fi
)

cs_sensor_policy_name=$(
    if [ -n "$FALCON_SENSOR_UPDATE_POLICY_NAME" ]; then
        echo "$FALCON_SENSOR_UPDATE_POLICY_NAME"
    else
        echo ""
    fi
)

cs_falcon_sensor_version_dec=$(
    re='^[0-9]\+$'
    if [ -n "$FALCON_SENSOR_VERSION_DECREMENT" ]; then
        if ! expr "$FALCON_SENSOR_VERSION_DECREMENT" : "$re" >/dev/null 2>&1; then
            die "The FALCON_SENSOR_VERSION_DECREMENT must be an integer greater than or equal to 0 or less than 5. FALCON_SENSOR_VERSION_DECREMENT: \"$FALCON_SENSOR_VERSION_DECREMENT\""
        elif [ "$FALCON_SENSOR_VERSION_DECREMENT" -lt 0 ] || [ "$FALCON_SENSOR_VERSION_DECREMENT" -gt 5 ]; then
            die "The FALCON_SENSOR_VERSION_DECREMENT must be an integer greater than or equal to 0 or less than 5. FALCON_SENSOR_VERSION_DECREMENT: \"$FALCON_SENSOR_VERSION_DECREMENT\""
        else
            echo "$FALCON_SENSOR_VERSION_DECREMENT"
        fi
    else
        echo "0"
    fi
)

# shellcheck disable=SC2001
proxy=$(
    proxy=""
    if [ -n "$FALCON_APH" ]; then
        proxy="$(echo "$FALCON_APH" | sed "s|http.*://||")"

        if [ -n "$FALCON_APP" ]; then
            proxy="$proxy:$FALCON_APP"
        fi
    fi

    if [ -n "$proxy" ]; then
        # Remove redundant quotes
        proxy="$(echo "$proxy" | sed "s/[\'\"]//g")"
        proxy="http://$proxy"
    fi
    echo "$proxy"
)

if [ -n "$FALCON_APD" ]; then
    cs_falcon_apd=$(
        case "${FALCON_APD}" in
            true)
                echo "true"
                ;;
            false)
                echo "false"
                ;;
            *)
                die "Unrecognized APD: ${FALCON_APD} value must be one of : [true|false]"
                ;;
        esac
    )
fi

if [ -n "$FALCON_BILLING" ]; then
    cs_falcon_billing=$(
        case "${FALCON_BILLING}" in
            default)
                echo "default"
                ;;
            metered)
                echo "metered"
                ;;
            *)
                die "Unrecognized BILLING: ${FALCON_BILLING} value must be one of : [default|metered]"
                ;;
        esac
    )
fi

if [ -n "$FALCON_BACKEND" ]; then
    cs_falcon_backend=$(
        case "${FALCON_BACKEND}" in
            auto)
                echo "auto"
                ;;
            bpf)
                echo "bpf"
                ;;
            kernel)
                echo "kernel"
                ;;
            *)
                die "Unrecognized BACKEND: ${FALCON_BACKEND} value must be one of : [auto|bpf|kernel]"
                ;;
        esac
    )
fi

if [ -n "$FALCON_TRACE" ]; then
    cs_falcon_trace=$(
        case "${FALCON_TRACE}" in
            none)
                echo "none"
                ;;
            err)
                echo "err"
                ;;
            warn)
                echo "warn"
                ;;
            info)
                echo "info"
                ;;
            debug)
                echo "debug"
                ;;
            *)
                die "Unrecognized TRACE: ${FALCON_TRACE} value must be one of : [none|err|warn|info|debug]"
                ;;
        esac
    )
fi

# Main migration function
main() {
    log "INFO" "Starting Falcon sensor migration from old CID to new CID"

    # Check if we are in recovery mode
    local recovery_mode=false
    if [ -f "$recovery_file" ]; then
        recovery_mode=true
        log "INFO" "Recovery file detected. Attempting to recover from previous migration attempt."
        if read_recovery_file "$recovery_file"; then
            log "INFO" "Loaded recovery data: old_aid=$old_aid"
        else
            log "WARNING" "Failed to load recovery data. Starting fresh migration."
            recovery_mode=false
        fi
    fi

    # Get the AID if not in recovery mode
    local cs_falcon_oauth_token
    if [ "$recovery_mode" = false ]; then
        # Get the AID and tags
        old_aid=$(get_aid)

        if [ -z "$old_aid" ]; then
            log "WARNING" "No AID found. The sensor may not be properly installed."
        else
            log "INFO" "Found AID: $old_aid"

            if [ "$migrate_tags" = "true" ]; then
                log "INFO" "Retrieving existing tags from current installation..."

                # Authenticate with the old CID
                cs_falcon_oauth_token=""
                cs_falcon_oauth_token=$(get_oauth_token "$OLD_FALCON_CLIENT_ID" "$OLD_FALCON_CLIENT_SECRET" "$old_cs_falcon_cloud")

                # Get the tags
                local tags
                tags=$(get_falcon_tags "$(cs_cloud "$old_cs_falcon_cloud")" "$cs_falcon_oauth_token" "$old_aid")

                # Split tags into sensor and falcon grouping tags
                local split_result
                split_result=$(split_tags "$tags")

                # Parse split result (semicolon-separated)
                sensor_tags=$(echo "$split_result" | cut -d ';' -f 1)
                falcon_tags=$(echo "$split_result" | cut -d ';' -f 2)

                log "INFO" "Found sensor tags: $sensor_tags"
                log "INFO" "Found falcon tags: $falcon_tags"

                # Create recovery file
                create_recovery_file "$sensor_tags" "$falcon_tags" "$old_aid" "$recovery_file"
            fi
        fi
    fi

    # Uninstall old sensor
    log "INFO" "Uninstalling old Falcon sensor..."

    # Set auth token for old CID (if needed)
    if [ -z "$cs_falcon_oauth_token" ]; then
        cs_falcon_oauth_token=$(get_oauth_token "$OLD_FALCON_CLIENT_ID" "$OLD_FALCON_CLIENT_SECRET" "$old_cs_falcon_cloud")
    fi

    # Get maintenance token if needed
    local cs_maintenance_token=""
    if [ -z "$FALCON_MAINTENANCE_TOKEN" ] && [ -n "$old_aid" ]; then
        cs_maintenance_token=$(get_maintenance_token "$old_aid" "$old_cs_falcon_cloud")
    fi

    # Perform uninstall
    cs_sensor_remove "$cs_maintenance_token"

    # Remove host from old console if requested
    if [ "${FALCON_REMOVE_HOST}" = "true" ] && [ -n "$old_aid" ]; then
        log "INFO" "Removing host from old Falcon CID console..."
        cs_remove_host_from_console "$old_aid" "$old_cs_falcon_cloud"
    fi

    # Install new sensor
    log "INFO" "Installing Falcon sensor to new CID..."

    # Set auth token for new CID
    cs_falcon_oauth_token=$(get_oauth_token "$NEW_FALCON_CLIENT_ID" "$NEW_FALCON_CLIENT_SECRET" "$new_cs_falcon_cloud")

    # Install the sensor
    cs_sensor_install

    # Register the sensor
    if [ -z "$FALCON_INSTALL_ONLY" ] || [ "${FALCON_INSTALL_ONLY}" = "false" ]; then
        log "INFO" "Registering Falcon sensor..."

        # Handle tags if migrating
        if [ "$migrate_tags" = "true" ]; then
            # Merge existing sensor tags with any new tags specified
            if [ -n "$FALCON_TAGS" ]; then
                sensor_tags=$(merge_tags "$sensor_tags" "$FALCON_TAGS")
                log "INFO" "Merged sensor tags: $sensor_tags"
            fi

            # Set the tags for the sensor install
            FALCON_TAGS="$sensor_tags"
        fi

        cs_sensor_register "$new_cs_falcon_cloud"
        cs_sensor_restart
    fi

    # Set Falcon grouping tags if migrating tags and falcon tags exist
    if [ "$migrate_tags" = "true" ] && [ -n "$falcon_tags" ]; then
        log "INFO" "Waiting for new sensor registration before setting Falcon grouping tags..."

        # Wait for the new AID to be available
        local max_wait=60
        local wait_count=0
        local new_aid=""

        while [ $wait_count -lt $max_wait ]; do
            new_aid=$(get_aid)
            if [ -n "$new_aid" ]; then
                break
            fi
            log "INFO" "Waiting for new AID to be available... ($wait_count/$max_wait)"
            wait_count=$((wait_count + 1))
            sleep 5
        done

        if [ -n "$new_aid" ]; then
            log "INFO" "New AID obtained: $new_aid"

            # Merge existing falcon tags with any new falcon tags specified
            if [ -n "$FALCON_GROUPING_TAGS" ]; then
                falcon_tags=$(merge_tags "$falcon_tags" "$FALCON_GROUPING_TAGS")
                log "INFO" "Merged Falcon grouping tags: $falcon_tags"
            fi

            # Format tags for API request
            local formatted_tags
            formatted_tags=$(format_tags_for_api "$falcon_tags" "FalconGroupingTags")

            # Set falcon tags via API
            log "INFO" "Setting Falcon grouping tags via API..."
            local max_attempts=5
            local attempt=1
            local success=false

            while [ $attempt -le $max_attempts ] && [ "$success" = false ]; do
                if set_falcon_tags "$(cs_cloud "$new_cs_falcon_cloud")" "$cs_falcon_oauth_token" "$new_aid" "$formatted_tags"; then
                    success=true
                else
                    log "WARNING" "Failed to set Falcon tags, attempt $attempt of $max_attempts"
                    attempt=$((attempt + 1))
                    sleep 5
                fi
            done

            if [ "$success" = true ]; then
                log "INFO" "Successfully set Falcon grouping tags"
            else
                log "WARNING" "Failed to set Falcon grouping tags after $max_attempts attempts"
            fi
        else
            log "WARNING" "Could not obtain new AID after $max_wait attempts"
        fi
    fi

    # Remove recovery file when done
    if [ -f "$recovery_file" ]; then
        log "INFO" "Removing recovery file..."
        rm -f "$recovery_file"
    fi

    log "INFO" "Falcon sensor migration completed successfully"
}
