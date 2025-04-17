#!/bin/bash

VERSION="1.0.0"

print_usage() {
    cat <<EOF

Usage: $0 [-h|--help]

Migrates the CrowdStrike Falcon Sensor from one CID to another.
Version: $VERSION

This script recognizes the following environmental variables:

Source CID Authentication:
    - SOURCE_FALCON_CLIENT_ID                  (default: unset)
        Your source CrowdStrike Falcon API client ID.

    - SOURCE_FALCON_CLIENT_SECRET              (default: unset)
        Your source CrowdStrike Falcon API client secret.

    - SOURCE_FALCON_ACCESS_TOKEN               (default: unset)
        Your source CrowdStrike Falcon API access token.
        If used, SOURCE_FALCON_CLOUD must also be set.

    - SOURCE_FALCON_CLOUD                      (default: unset)
        The cloud region where your source CrowdStrike Falcon instance is hosted.
        Required if using SOURCE_FALCON_ACCESS_TOKEN.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1'].

Target CID Authentication:
    - TARGET_FALCON_CLIENT_ID                  (default: unset)
        Your target CrowdStrike Falcon API client ID.

    - TARGET_FALCON_CLIENT_SECRET              (default: unset)
        Your target CrowdStrike Falcon API client secret.

    - TARGET_FALCON_ACCESS_TOKEN               (default: unset)
        Your target CrowdStrike Falcon API access token.
        If used, TARGET_FALCON_CLOUD must also be set.

    - TARGET_FALCON_CLOUD                      (default: unset)
        The cloud region where your target CrowdStrike Falcon instance is hosted.
        Required if using TARGET_FALCON_ACCESS_TOKEN.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1'].

Migration Options:
    - MIGRATE_TAGS                             (default: false)
        Migrate the host's existing tags to the target CID.
        Accepted values are ['true', 'false'].

    - TARGET_FALCON_TAGS                       (default: unset)
        A comma separated list of tags for the sensor in the target CID.
        If MIGRATE_TAGS is true, these tags will be added in addition to the existing tags.

Other Options:
    - FALCON_MAINTENANCE_TOKEN                 (default: unset)
        Sensor uninstall maintenance token used to unlock sensor uninstallation.
        If not provided, the script will try to retrieve it from the API.

    - FALCON_PROVISIONING_TOKEN                (default: unset)
        The provisioning token to use for installing the sensor in the target CID.
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

# Main function to orchestrate the migration process
main() {
    echo "Starting Falcon Sensor migration from source CID to target CID..."
    
    # Initialize variables and settings
    setup_variables
    
    # Check if Falcon sensor is installed
    echo -n 'Checking if Falcon Sensor is running ... '
    cs_sensor_is_running
    echo '[ Running ]'
    
    # Get source info before uninstall
    echo -n 'Getting source sensor information ... '
    get_source_sensor_info
    echo '[ Ok ]'
    
    # Uninstall current sensor
    echo -n 'Uninstalling source Falcon Sensor ... '
    uninstall_source_sensor
    echo '[ Ok ]'
    
    # Install sensor with target CID
    echo -n 'Installing Falcon Sensor with target CID ... '
    install_target_sensor
    echo '[ Ok ]'
    
    # Register and restart sensor
    echo -n 'Registering Falcon Sensor ... '
    register_sensor
    echo '[ Ok ]'
    
    echo -n 'Restarting Falcon Sensor ... '
    restart_sensor
    echo '[ Ok ]'
    
    echo "Falcon Sensor successfully migrated to target CID."
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

# Get sensor information from the source CID (including tags)
get_source_sensor_info() {
    # Set up the source credentials
    echo "Setting up source credentials..."
    source_get_oauth_token
    
    # Get existing tags if tag migration is enabled
    if [ "${MIGRATE_TAGS}" = "true" ] && [ -n "$aid" ]; then
        echo "Retrieving existing tags for host with AID: $aid"
        get_source_tags
    fi
}

# Set up source credentials for API access
setup_source_credentials() {
    # We need to set proper environment variables for the get_oauth_token function
    FALCON_CLIENT_ID="$SOURCE_FALCON_CLIENT_ID"
    FALCON_CLIENT_SECRET="$SOURCE_FALCON_CLIENT_SECRET"
    FALCON_ACCESS_TOKEN="$SOURCE_FALCON_ACCESS_TOKEN"
    FALCON_CLOUD="$SOURCE_FALCON_CLOUD"
    
    source_get_oauth_token
}

# Uninstall the source sensor
uninstall_source_sensor() {
    # We need source authentication to get maintenance token
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

# Install sensor with target CID
install_target_sensor() {
    # Switch to target credentials
    echo "Setting up target credentials..."
    target_get_oauth_token
    
    # Get target CID
    target_cid=$(get_target_falcon_cid)
    echo "Target CID: $target_cid"
    
    # Get provisioning token if needed
    if [ -z "$FALCON_PROVISIONING_TOKEN" ]; then
        echo "No provisioning token provided, checking if one is required..."
        target_provisioning_token=$(get_target_provisioning_token)
        if [ -n "$target_provisioning_token" ]; then
            FALCON_PROVISIONING_TOKEN="$target_provisioning_token"
            echo "Retrieved provisioning token from target CID."
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
    if [ -z "$target_cid" ]; then
        target_cid=$(get_target_falcon_cid)
    fi

    # If cs_falcon_token is not set, try getting it from api
    if [ -z "$FALCON_PROVISIONING_TOKEN" ] && [ -n "$target_provisioning_token" ]; then
        FALCON_PROVISIONING_TOKEN="$target_provisioning_token"
    fi

    # Assemble the registration arguments
    # add the cid to the params
    cs_falcon_args=--cid="${target_cid}"
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

    echo "Registering sensor with target CID: $target_cid"
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
