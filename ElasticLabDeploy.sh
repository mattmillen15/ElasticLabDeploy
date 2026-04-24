#!/usr/bin/env bash
set -euo pipefail

# Lab-only bootstrap for a minimal self-managed Elastic Stack + Fleet Server +
# Elastic Defend endpoint policy using the EDRComplete preset (aggressive EDR).
#
# Requires: docker, Docker Compose (plugin or standalone), curl, jq, openssl
# Example:
#   FLEET_PUBLIC_URL=http://192.168.1.50:8220 \
#   ELASTIC_PUBLIC_URL=http://192.168.1.50:9200 \
#   ./ElasticLabDeploy.sh fresh-install

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

STACK_VERSION="${STACK_VERSION:-9.2.3}"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-goad_edr_lab}"
LAB_ROOT="${LAB_ROOT:-${SCRIPT_DIR}/runtime}"
OUTPUT_DIR="${OUTPUT_DIR:-${LAB_ROOT}/output}"
COMPOSE_FILE="${LAB_ROOT}/docker-compose.yml"
ENV_FILE="${LAB_ROOT}/.env"
SECRETS_FILE="${LAB_ROOT}/secrets.env"

ES_PORT="${ES_PORT:-9200}"
KIBANA_PORT="${KIBANA_PORT:-5601}"
FLEET_SERVER_PORT="${FLEET_SERVER_PORT:-8220}"
ES_HEAP="${ES_HEAP:-1g}"
KIBANA_NODE_OPTIONS="${KIBANA_NODE_OPTIONS:---max-old-space-size=1024}"
KIBANA_WAIT_ATTEMPTS="${KIBANA_WAIT_ATTEMPTS:-300}"
FLEET_SETUP_ATTEMPTS="${FLEET_SETUP_ATTEMPTS:-240}"
ENABLE_PREBUILT_RULES="${ENABLE_PREBUILT_RULES:-true}"
ENFORCE_ENDPOINT_HARDENING="${ENFORCE_ENDPOINT_HARDENING:-true}"
ENABLE_OSQUERY_MANAGER="${ENABLE_OSQUERY_MANAGER:-true}"
ENABLE_WINDOWS_INTEGRATION="${ENABLE_WINDOWS_INTEGRATION:-true}"
ENABLE_THREAT_INTEL="${ENABLE_THREAT_INTEL:-true}"
REQUIRE_THREAT_INTEL="${REQUIRE_THREAT_INTEL:-false}"
THREAT_INTEL_PACKAGE_CANDIDATES="${THREAT_INTEL_PACKAGE_CANDIDATES:-ti_abusech,threat_intel,ti_otx,ti_opencti,ti_anomali,ti_misp}"
REQUIRE_ADVANCED_PROTECTION="${REQUIRE_ADVANCED_PROTECTION:-true}"
DISABLE_WINDOWS_LSASS_PROTECTION="${DISABLE_WINDOWS_LSASS_PROTECTION:-true}"

FLEET_SERVER_CONTAINER="${FLEET_SERVER_CONTAINER:-goad-edr-lab-fleet-server}"
FLEET_SERVER_STATE_VOLUME="${FLEET_SERVER_STATE_VOLUME:-goad_edr_lab_fleet_state}"
FLEET_SERVER_MODE="${FLEET_SERVER_MODE:-auto}"
AUTO_INSTALL_PREREQS="${AUTO_INSTALL_PREREQS:-true}"
AUTO_CONFIRM="${AUTO_CONFIRM:-false}"
SELF_ELEVATE="${SELF_ELEVATE:-true}"
ENROLLMENT_HTTP_PORT="${ENROLLMENT_HTTP_PORT:-8088}"
ENROLLMENT_HTTP_IFACE="${ENROLLMENT_HTTP_IFACE:-eth0}"
ENROLLMENT_HTTP_BIND_IP="${ENROLLMENT_HTTP_BIND_IP:-}"

FLEET_SERVER_POLICY_NAME="${FLEET_SERVER_POLICY_NAME:-GOAD Fleet Server Policy}"
ENDPOINT_POLICY_NAME="${ENDPOINT_POLICY_NAME:-GOAD Windows EDR (Intense-like)}"
ENDPOINT_INTEGRATION_NAME="${ENDPOINT_INTEGRATION_NAME:-Elastic Defend - GOAD EDRComplete}"
OSQUERY_INTEGRATION_NAME="${OSQUERY_INTEGRATION_NAME:-Osquery Manager - GOAD}"
WINDOWS_INTEGRATION_NAME="${WINDOWS_INTEGRATION_NAME:-Windows Telemetry - GOAD}"
THREAT_INTEL_INTEGRATION_NAME_PREFIX="${THREAT_INTEL_INTEGRATION_NAME_PREFIX:-Threat Intel - GOAD}"
ENROLLMENT_KEY_NAME="${ENROLLMENT_KEY_NAME:-goad-endpoint-enroll}"

KIBANA_URL="http://127.0.0.1:${KIBANA_PORT}"
ES_URL_LOCAL="http://127.0.0.1:${ES_PORT}"
LAST_ENDPOINT_PACKAGE_POLICY_ITEM=""

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

is_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

command_requires_root() {
  local cmd="${1:-menu}"
  case "${cmd}" in
    bootstrap|fresh-install|install-prereqs|reset|reset-lab|refresh|rebuild-lab|recover-fleet-server|menu)
      return 0
      ;;
  esac
  return 1
}

maybe_self_elevate() {
  local cmd="${1:-menu}"
  [[ "${SELF_ELEVATE}" == "true" ]] || return 0
  command_requires_root "${cmd}" || return 0
  is_root && return 0
  command -v sudo >/dev/null 2>&1 || die "Command '${cmd}' requires root. Re-run with sudo or install sudo."
  log "Re-running as sudo for '${cmd}'"
  exec sudo -E bash "$0" "$@"
}

docker_compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
    return 0
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
    return 0
  fi
  return 127
}

ensure_docker_compose_available() {
  docker_compose_cmd version >/dev/null 2>&1 || die "Docker Compose is required (docker compose or docker-compose)."
}

compose_cmd() {
  COMPOSE_PROJECT="${COMPOSE_PROJECT}" docker_compose_cmd \
    -p "${COMPOSE_PROJECT}" \
    --env-file "${ENV_FILE}" \
    -f "${COMPOSE_FILE}" \
    "$@"
}

container_state() {
  local name="$1"
  if docker inspect "${name}" >/dev/null 2>&1; then
    docker inspect -f 'status={{.State.Status}} restart={{.RestartCount}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}' "${name}" 2>/dev/null || true
    return 0
  fi
  printf 'status=missing\n'
}

container_restart_count() {
  local name="$1"
  if docker inspect "${name}" >/dev/null 2>&1; then
    docker inspect -f '{{.RestartCount}}' "${name}" 2>/dev/null || printf '0'
    return 0
  fi
  printf '0\n'
}

dump_stack_diagnostics() {
  log "Dumping stack diagnostics for troubleshooting"
  compose_cmd ps || true
  compose_cmd logs --tail 200 es01 || true
  compose_cmd logs --tail 200 kibana || true
}

load_or_create_secrets() {
  local env_elastic_password="${ELASTIC_PASSWORD:-}"
  local env_kibana_system_password="${KIBANA_SYSTEM_PASSWORD:-}"
  local env_lab_password="${LAB_PASSWORD:-}"
  local env_lab_kibana_password="${LAB_KIBANA_SYSTEM_PASSWORD:-}"

  mkdir -p "${LAB_ROOT}"

  if [[ -f "${SECRETS_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${SECRETS_FILE}"
  fi

  # Precedence: explicit env vars > LAB_* vars > existing secrets file > defaults.
  ELASTIC_PASSWORD="${env_elastic_password:-${env_lab_password:-${ELASTIC_PASSWORD:-P@ssw0rd}}}"
  KIBANA_SYSTEM_PASSWORD="${env_kibana_system_password:-${env_lab_kibana_password:-${KIBANA_SYSTEM_PASSWORD:-${ELASTIC_PASSWORD}}}}"
  KIBANA_KEY_1="${KIBANA_KEY_1:-$(openssl rand -hex 32)}"
  KIBANA_KEY_2="${KIBANA_KEY_2:-$(openssl rand -hex 32)}"
  KIBANA_KEY_3="${KIBANA_KEY_3:-$(openssl rand -hex 32)}"

  cat > "${SECRETS_FILE}" <<EOF
ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
KIBANA_SYSTEM_PASSWORD=${KIBANA_SYSTEM_PASSWORD}
KIBANA_KEY_1=${KIBANA_KEY_1}
KIBANA_KEY_2=${KIBANA_KEY_2}
KIBANA_KEY_3=${KIBANA_KEY_3}
EOF
  chmod 600 "${SECRETS_FILE}"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

load_existing_secrets_if_present() {
  if [[ -f "${SECRETS_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${SECRETS_FILE}"
  fi

  ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-${LAB_PASSWORD:-P@ssw0rd}}"
  KIBANA_SYSTEM_PASSWORD="${KIBANA_SYSTEM_PASSWORD:-${LAB_KIBANA_SYSTEM_PASSWORD:-${ELASTIC_PASSWORD}}}"
}

load_enrollment_env_if_present() {
  local enrollment_file="${OUTPUT_DIR}/enrollment.env"
  if [[ -f "${enrollment_file}" ]]; then
    # shellcheck disable=SC1090
    source "${enrollment_file}"
  fi

  if [[ -z "${FLEET_PUBLIC_URL:-}" && -n "${FLEET_URL:-}" ]]; then
    FLEET_PUBLIC_URL="${FLEET_URL}"
  fi
  if [[ -z "${ELASTIC_PUBLIC_URL:-}" && -n "${ELASTICSEARCH_URL:-}" ]]; then
    ELASTIC_PUBLIC_URL="${ELASTICSEARCH_URL}"
  fi
}

ensure_vm_max_map_count() {
  if [[ "$(uname -s)" != "Linux" ]] || ! command -v sysctl >/dev/null 2>&1; then
    return 0
  fi

  local vmmax
  vmmax="$(sysctl -n vm.max_map_count 2>/dev/null || printf '0')"
  if [[ "${vmmax}" =~ ^[0-9]+$ ]] && (( vmmax < 262144 )); then
    log "Setting vm.max_map_count=262144"
    sysctl -w vm.max_map_count=262144 >/dev/null
  fi
}

start_docker_service_if_possible() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    return 0
  fi
  if command -v service >/dev/null 2>&1; then
    service docker start >/dev/null 2>&1 || true
  fi
}

install_first_available_pkg() {
  local manager="$1"
  shift
  local pkg
  for pkg in "$@"; do
    [[ -n "${pkg}" ]] || continue
    case "${manager}" in
      apt)
        if apt-get install -y "${pkg}" >/dev/null 2>&1; then
          log "Installed package '${pkg}'"
          return 0
        fi
        ;;
      dnf)
        if dnf install -y "${pkg}" >/dev/null 2>&1; then
          log "Installed package '${pkg}'"
          return 0
        fi
        ;;
      yum)
        if yum install -y "${pkg}" >/dev/null 2>&1; then
          log "Installed package '${pkg}'"
          return 0
        fi
        ;;
      *)
        return 1
        ;;
    esac
  done
  return 1
}

install_host_prereqs() {
  if [[ "${AUTO_INSTALL_PREREQS}" != "true" ]]; then
    return 0
  fi

  if [[ "$(uname -s)" != "Linux" ]]; then
    log "Automatic prerequisite install is only implemented for Linux; skipping."
    return 0
  fi

  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    log "Installing host prerequisites with apt-get"
    apt-get update -y >/dev/null
    apt-get install -y ca-certificates curl jq openssl python3 tar lsof gawk sed coreutils >/dev/null
    if ! command -v docker >/dev/null 2>&1; then
      install_first_available_pkg apt docker.io docker-ce moby-engine || die "Unable to install Docker with apt-get"
    fi
    if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
      install_first_available_pkg apt docker-compose-plugin docker-compose-v2 docker-compose || die "Unable to install Docker Compose with apt-get"
    fi
    start_docker_service_if_possible
    ensure_vm_max_map_count
    return 0
  fi

  if command -v dnf >/dev/null 2>&1; then
    log "Installing host prerequisites with dnf"
    dnf install -y ca-certificates curl jq openssl python3 tar lsof gawk sed coreutils >/dev/null
    if ! command -v docker >/dev/null 2>&1; then
      install_first_available_pkg dnf moby-engine docker-ce docker || die "Unable to install Docker with dnf"
    fi
    if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
      install_first_available_pkg dnf docker-compose-plugin docker-compose || die "Unable to install Docker Compose with dnf"
    fi
    start_docker_service_if_possible
    ensure_vm_max_map_count
    return 0
  fi

  if command -v yum >/dev/null 2>&1; then
    log "Installing host prerequisites with yum"
    yum install -y ca-certificates curl jq openssl python3 tar lsof gawk sed coreutils >/dev/null
    if ! command -v docker >/dev/null 2>&1; then
      install_first_available_pkg yum docker-ce docker || die "Unable to install Docker with yum"
    fi
    if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
      install_first_available_pkg yum docker-compose-plugin docker-compose || die "Unable to install Docker Compose with yum"
    fi
    start_docker_service_if_possible
    ensure_vm_max_map_count
    return 0
  fi

  die "Unsupported package manager for AUTO_INSTALL_PREREQS=true. Install docker/curl/jq/openssl/python3 manually."
}

check_host_prereqs() {
  if [[ "$(uname -s)" == "Linux" ]] && command -v sysctl >/dev/null 2>&1; then
    local vmmax
    vmmax="$(sysctl -n vm.max_map_count 2>/dev/null || printf '0')"
    if [[ "${vmmax}" =~ ^[0-9]+$ ]] && (( vmmax < 262144 )); then
      if is_root; then
        ensure_vm_max_map_count
      else
        die "vm.max_map_count is ${vmmax}; set it to at least 262144 (sudo sysctl -w vm.max_map_count=262144)"
      fi
    fi
  fi

  if [[ "$(uname -s)" == "Linux" ]] && [[ -r /proc/meminfo ]]; then
    local mem_kb
    mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || printf '0')"
    if [[ "${mem_kb}" =~ ^[0-9]+$ ]] && (( mem_kb < 6291456 )); then
      log "Host RAM appears below 6 GB; Kibana may restart during bootstrap. Consider adding RAM or lowering ES_HEAP."
    fi
  fi
}

detect_primary_ip() {
  if command -v hostname >/dev/null 2>&1; then
    local hip
    hip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    if [[ -n "${hip}" ]]; then
      printf '%s\n' "${hip}"
      return 0
    fi
  fi

  if command -v ip >/dev/null 2>&1; then
    local ipaddr
    ipaddr="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' || true)"
    if [[ -n "${ipaddr}" ]]; then
      printf '%s\n' "${ipaddr}"
      return 0
    fi
  fi

  return 1
}

json_escape() {
  jq -Rn --arg v "$1" '$v'
}

kibana_get() {
  local path="$1"
  curl -fsS -u "elastic:${ELASTIC_PASSWORD}" \
    -H 'Accept: application/json' \
    "${KIBANA_URL}${path}"
}

curl_json_request_raw() {
  local method="$1"
  local url="$2"
  local body="${3-}"
  local auth_kind="${4:-kibana}"
  local tmp_body
  [[ -n "${body}" ]] || body='{}'

  jq -ce . >/dev/null <<<"${body}" || die "Refusing to send invalid JSON payload to ${url}"

  tmp_body="$(mktemp)"
  printf '%s' "${body}" > "${tmp_body}"

  local -a args=(
    -s
    -H 'Content-Type: application/json'
    -H 'Accept: application/json'
    -w '\n%{http_code}'
    -X "${method}"
    "${url}"
    --data-binary "@${tmp_body}"
  )

  case "${auth_kind}" in
    kibana)
      args=( -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: goad-edr-bootstrap' "${args[@]}" )
      ;;
    es)
      args=( -u "elastic:${ELASTIC_PASSWORD}" "${args[@]}" )
      ;;
    *)
      rm -f "${tmp_body}"
      die "Unsupported auth kind '${auth_kind}'"
      ;;
  esac

  local resp
  resp="$(curl "${args[@]}" 2>/dev/null || true)"
  rm -f "${tmp_body}"
  printf '%s\n' "${resp}"
}

kibana_post() {
  local path="$1"
  local body="${2-}"
  local resp http_code payload
  [[ -n "${body}" ]] || body='{}'
  resp="$(curl_json_request_raw POST "${KIBANA_URL}${path}" "${body}" kibana)"
  http_code="$(tail -n1 <<<"${resp}")"
  payload="${resp%$'\n'*}"
  [[ "${http_code}" == "200" || "${http_code}" == "201" || "${http_code}" == "204" ]] || return 1
  printf '%s\n' "${payload}"
}

kibana_post_raw() {
  local path="$1"
  local body="${2-}"
  [[ -n "${body}" ]] || body='{}'
  curl_json_request_raw POST "${KIBANA_URL}${path}" "${body}" kibana
}

kibana_post_checked() {
  local path="$1"
  local body="${2-}"
  local resp http_code payload
  [[ -n "${body}" ]] || body='{}'
  resp="$(kibana_post_raw "${path}" "${body}")"
  http_code="$(tail -n1 <<<"${resp}")"
  payload="${resp%$'\n'*}"

  if [[ "${http_code}" == "200" || "${http_code}" == "201" || "${http_code}" == "204" ]]; then
    printf '%s\n' "${payload}"
    return 0
  fi

  log "Kibana POST failed: path=${path} http=${http_code:-n/a}"
  log "Kibana POST payload: $(jq -c . <<<"${body}" 2>/dev/null || printf '%s' "${body}")"
  printf '%s\n' "${payload}" >&2
  return 1
}

kibana_put() {
  local path="$1"
  local body="${2-}"
  local resp http_code payload
  [[ -n "${body}" ]] || body='{}'
  resp="$(curl_json_request_raw PUT "${KIBANA_URL}${path}" "${body}" kibana)"
  http_code="$(tail -n1 <<<"${resp}")"
  payload="${resp%$'\n'*}"
  [[ "${http_code}" == "200" || "${http_code}" == "201" || "${http_code}" == "204" ]] || return 1
  printf '%s\n' "${payload}"
}

kibana_put_raw() {
  local path="$1"
  local body="${2-}"
  [[ -n "${body}" ]] || body='{}'
  curl_json_request_raw PUT "${KIBANA_URL}${path}" "${body}" kibana
}

kibana_put_checked() {
  local path="$1"
  local body="${2-}"
  local resp http_code payload
  [[ -n "${body}" ]] || body='{}'
  resp="$(kibana_put_raw "${path}" "${body}")"
  http_code="$(tail -n1 <<<"${resp}")"
  payload="${resp%$'\n'*}"

  if [[ "${http_code}" == "200" || "${http_code}" == "201" || "${http_code}" == "204" ]]; then
    printf '%s\n' "${payload}"
    return 0
  fi

  log "Kibana PUT failed: path=${path} http=${http_code:-n/a}"
  printf '%s\n' "${payload}" >&2
  return 1
}

es_post() {
  local path="$1"
  local body="${2:-}"
  if [[ -n "${body}" ]]; then
    local resp http_code payload
    resp="$(curl_json_request_raw POST "${ES_URL_LOCAL}${path}" "${body}" es)"
    http_code="$(tail -n1 <<<"${resp}")"
    payload="${resp%$'\n'*}"
    [[ "${http_code}" == "200" || "${http_code}" == "201" || "${http_code}" == "204" ]] || return 1
    printf '%s\n' "${payload}"
    return 0
  fi
  curl -fsS -u "elastic:${ELASTIC_PASSWORD}" -X POST "${ES_URL_LOCAL}${path}"
}

wait_for_elasticsearch() {
  log "Waiting for Elasticsearch on ${ES_URL_LOCAL}"
  local i
  for i in $(seq 1 120); do
    if curl -fsS -u "elastic:${ELASTIC_PASSWORD}" \
      "${ES_URL_LOCAL}/_cluster/health?wait_for_status=yellow&timeout=1s" >/dev/null 2>&1; then
      return 0
    fi
    if (( i % 20 == 0 )); then
      log "Elasticsearch not ready yet (attempt ${i}/120). $(container_state "${COMPOSE_PROJECT}_es01")"
    fi
    sleep 3
  done
  dump_stack_diagnostics
  die "Elasticsearch did not become ready in time"
}

wait_for_kibana() {
  log "Waiting for Kibana on ${KIBANA_URL}"
  local i resp restarts
  for i in $(seq 1 "${KIBANA_WAIT_ATTEMPTS}"); do
    resp="$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
      -H 'Accept: application/json' \
      "${KIBANA_URL}/api/status" 2>/dev/null || true)"
    if [[ -n "${resp}" ]] && jq -e '.status.overall.level == "available"' >/dev/null 2>&1 <<<"${resp}"; then
      return 0
    fi
    restarts="$(container_restart_count "${COMPOSE_PROJECT}_kibana")"
    if [[ "${restarts}" =~ ^[0-9]+$ ]] && (( restarts >= 5 )); then
      log "Kibana crash-loop detected (restart=${restarts})."
      dump_stack_diagnostics
      die "Kibana is restarting repeatedly; check kibana logs above for FATAL/ERROR details."
    fi
    if (( i % 20 == 0 )); then
      log "Kibana not ready yet (attempt ${i}/${KIBANA_WAIT_ATTEMPTS}). $(container_state "${COMPOSE_PROJECT}_kibana")"
    fi
    sleep 3
  done
  dump_stack_diagnostics
  die "Kibana did not become ready in time"
}

host_port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn "( sport = :${port} )" 2>/dev/null | awk 'NR > 1 {found=1} END {exit found ? 0 : 1}'
    return $?
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"${port}" -sTCP:LISTEN -Pn >/dev/null 2>&1
    return $?
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk -v p=":${port}" '$4 ~ p "$" {found=1} END {exit found ? 0 : 1}'
    return $?
  fi
  return 1
}

fleet_server_status_json() {
  local base_url="${1:-${FLEET_PUBLIC_URL}}"
  curl -fsS "${base_url}/api/status" 2>/dev/null || return 1
}

fleet_server_is_healthy() {
  local base_url="${1:-${FLEET_PUBLIC_URL}}"
  local resp
  resp="$(fleet_server_status_json "${base_url}" || true)"
  [[ -n "${resp}" ]] || return 1
  jq -e '(.status // "") | ascii_upcase == "HEALTHY"' >/dev/null 2>&1 <<<"${resp}"
}

wait_for_fleet_server() {
  local base_url="${1:-http://127.0.0.1:${FLEET_SERVER_PORT}}"
  local url="${base_url}/api/status"
  local check_container="${2:-true}"
  log "Waiting for Fleet Server on ${url}"
  local i resp restarts
  for i in $(seq 1 120); do
    resp="$(curl -s "${url}" 2>/dev/null || true)"
    if jq -e '(.status // "") | ascii_upcase == "HEALTHY"' >/dev/null 2>&1 <<<"${resp}"; then
      return 0
    fi
    if [[ "${check_container}" == "true" ]]; then
      restarts="$(container_restart_count "${FLEET_SERVER_CONTAINER}")"
      if [[ "${restarts}" =~ ^[0-9]+$ ]] && (( restarts >= 8 )); then
        log "Fleet Server crash-loop detected (restart=${restarts})."
        docker logs --tail 200 "${FLEET_SERVER_CONTAINER}" || true
        die "Fleet Server is restarting repeatedly; see logs above."
      fi
      if (( i % 20 == 0 )); then
        log "Fleet Server not healthy yet (attempt ${i}/120). $(container_state "${FLEET_SERVER_CONTAINER}")"
      fi
    elif (( i % 20 == 0 )); then
      log "Fleet Server not healthy yet (attempt ${i}/120) at ${base_url}"
    fi
    sleep 3
  done
  if [[ "${check_container}" == "true" ]]; then
    docker logs --tail 200 "${FLEET_SERVER_CONTAINER}" || true
  fi
  log "Fleet Server status payload (last seen): ${resp:-<none>}"
  die "Fleet Server did not become healthy in time"
}

write_compose_files() {
  mkdir -p "${LAB_ROOT}" "${OUTPUT_DIR}"

  cat > "${ENV_FILE}" <<ENVEOF
STACK_VERSION=${STACK_VERSION}
ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
KIBANA_KEY_1=${KIBANA_KEY_1}
KIBANA_KEY_2=${KIBANA_KEY_2}
KIBANA_KEY_3=${KIBANA_KEY_3}
ES_PORT=${ES_PORT}
KIBANA_PORT=${KIBANA_PORT}
ES_HEAP=${ES_HEAP}
KIBANA_NODE_OPTIONS=${KIBANA_NODE_OPTIONS}
KIBANA_SYSTEM_PASSWORD=${KIBANA_SYSTEM_PASSWORD}
ELASTIC_PUBLIC_URL=${ELASTIC_PUBLIC_URL}
FLEET_PUBLIC_URL=${FLEET_PUBLIC_URL}
ENVEOF

  cat > "${COMPOSE_FILE}" <<'YAMLEOF'
services:
  es01:
    image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
    container_name: ${COMPOSE_PROJECT:-goad_edr_lab}_es01
    restart: unless-stopped
    environment:
      discovery.type: single-node
      xpack.security.enabled: "true"
      xpack.security.http.ssl.enabled: "false"
      xpack.security.authc.api_key.enabled: "true"
      xpack.license.self_generated.type: basic
      ELASTIC_PASSWORD: ${ELASTIC_PASSWORD}
      ES_JAVA_OPTS: -Xms${ES_HEAP} -Xmx${ES_HEAP}
    ports:
      - "${ES_PORT}:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:${STACK_VERSION}
    container_name: ${COMPOSE_PROJECT:-goad_edr_lab}_kibana
    restart: unless-stopped
    depends_on:
      - es01
    environment:
      ELASTICSEARCH_HOSTS: http://es01:9200
      ELASTICSEARCH_USERNAME: kibana_system
      ELASTICSEARCH_PASSWORD: ${KIBANA_SYSTEM_PASSWORD}
      SERVER_PUBLICBASEURL: http://127.0.0.1:${KIBANA_PORT}
      NODE_OPTIONS: ${KIBANA_NODE_OPTIONS}
      XPACK_FLEET_AGENTS_ENABLED: "true"
      XPACK_FLEET_AGENTS_ELASTICSEARCH_HOSTS: '["${ELASTIC_PUBLIC_URL}"]'
      XPACK_FLEET_AGENTS_FLEET_SERVER_HOSTS: '["${FLEET_PUBLIC_URL}"]'
      XPACK_SECURITY_ENCRYPTIONKEY: ${KIBANA_KEY_1}
      XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY: ${KIBANA_KEY_2}
      XPACK_REPORTING_ENCRYPTIONKEY: ${KIBANA_KEY_3}
    ports:
      - "${KIBANA_PORT}:5601"
    volumes:
      - kibanadata:/usr/share/kibana/data

volumes:
  esdata:
  kibanadata:
YAMLEOF
}

compose_up_es() {
  log "Starting Elasticsearch via Docker Compose"
  compose_cmd up -d es01
}

compose_up_kibana() {
  log "Starting Kibana via Docker Compose"
  compose_cmd up -d kibana
}

set_kibana_system_password() {
  log "Setting kibana_system password for Kibana server auth"
  local payload i
  payload="$(jq -n --arg pw "${KIBANA_SYSTEM_PASSWORD}" '{password: $pw}')"
  for i in $(seq 1 40); do
    if curl -fsS -u "elastic:${ELASTIC_PASSWORD}" \
      -H 'Content-Type: application/json' \
      -X POST "${ES_URL_LOCAL}/_security/user/kibana_system/_password" \
      --data-binary "${payload}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 3
  done
  die "Failed to set kibana_system password in Elasticsearch"
}

fleet_api_setup() {
  log "Initializing Fleet in Kibana"
  local i http_code resp
  for i in $(seq 1 "${FLEET_SETUP_ATTEMPTS}"); do
    resp="$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
      -H 'kbn-xsrf: goad-edr-bootstrap' \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json' \
      -w '\n%{http_code}' \
      -X POST "${KIBANA_URL}/api/fleet/setup" \
      -d '{}' 2>/dev/null || true)"
    http_code="$(tail -n1 <<<"${resp}")"

    if [[ "${http_code}" == "200" ]]; then
      return 0
    fi

    # If Fleet APIs are already reachable, continue even if setup endpoint is noisy.
    if kibana_get '/api/fleet/agent_policies?perPage=1' >/dev/null 2>&1; then
      log "Fleet APIs are reachable; continuing."
      return 0
    fi

    if (( i % 20 == 0 )); then
      log "Fleet setup not ready yet (attempt ${i}/${FLEET_SETUP_ATTEMPTS}, http=${http_code:-n/a})"
    fi
    sleep 3
  done
  log "Fleet setup last response payload:"
  printf '%s\n' "${resp%$'\n'*}" >&2
  die "Fleet setup API did not succeed"
}

start_trial_if_possible() {
  log "Starting 30-day trial license (for full Elastic Defend features)"
  local resp http_code payload
  resp="$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
    -w '\n%{http_code}' \
    -X POST "${ES_URL_LOCAL}/_license/start_trial?acknowledge=true" 2>/dev/null || true)"
  http_code="$(tail -n1 <<<"${resp}")"
  payload="${resp%$'\n'*}"

  if [[ "${http_code}" == "200" || "${http_code}" == "201" ]]; then
    log "Trial license start request accepted"
    return 0
  fi

  # Common and expected in labs when trial was already activated before.
  log "Trial license start skipped (HTTP ${http_code:-n/a})"
  if [[ -n "${payload}" ]]; then
    log "License API response: $(jq -c '.' <<<"${payload}" 2>/dev/null || printf '%s' "${payload}")"
  fi
}

current_license_type() {
  curl -s -u "elastic:${ELASTIC_PASSWORD}" "${ES_URL_LOCAL}/_license" 2>/dev/null | jq -r '.license.type // empty'
}

ensure_advanced_license() {
  local license_type
  license_type="$(current_license_type || true)"
  if [[ "${license_type}" == "trial" || "${license_type}" == "platinum" || "${license_type}" == "enterprise" ]]; then
    log "Advanced protections available under license type '${license_type}'"
    return 0
  fi

  start_trial_if_possible
  sleep 1
  license_type="$(current_license_type || true)"
  if [[ "${license_type}" == "trial" || "${license_type}" == "platinum" || "${license_type}" == "enterprise" ]]; then
    log "Advanced protections enabled under license type '${license_type}'"
    return 0
  fi

  if [[ "${REQUIRE_ADVANCED_PROTECTION}" == "true" ]]; then
    die "License type '${license_type:-unknown}' does not support full prevention features. Start trial manually or set REQUIRE_ADVANCED_PROTECTION=false."
  fi

  log "WARNING: License type '${license_type:-unknown}' limits prevention features (memory/ransomware/behavior/ASR)."
}

get_latest_package_version() {
  local pkg="$1"
  kibana_get "/api/fleet/epm/packages/${pkg}" | jq -r '
    .item.version //
    .item.latestVersion //
    .response[0].version //
    empty
  ' | head -n1
}

get_package_status() {
  local pkg="$1"
  kibana_get "/api/fleet/epm/packages/${pkg}" | jq -r '
    .item.status //
    .response[0].status //
    empty
  ' | head -n1
}

ensure_package_installed() {
  local pkg="$1"
  local ver
  local status
  local resp
  local http_code
  local query
  local installed_ok=0
  local -a query_variants=(
    ""
    "?ignoreUnverified=true"
    "?force=true"
    "?force=true&ignoreUnverified=true"
  )

  ver="$(get_latest_package_version "${pkg}")"
  [[ -n "${ver}" ]] || die "Unable to resolve latest version for package '${pkg}'"

  status="$(get_package_status "${pkg}" || true)"
  if [[ "${status}" == "installed" ]]; then
    log "Package '${pkg}' is already installed; skipping install"
    printf '%s\n' "${ver}"
    return 0
  fi

  log "Installing/updating Fleet package '${pkg}' (${ver})"
  for query in "${query_variants[@]}"; do
    resp="$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
      -H 'kbn-xsrf: goad-edr-bootstrap' \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json' \
      -w '\n%{http_code}' \
      -X POST "${KIBANA_URL}/api/fleet/epm/packages/${pkg}/${ver}${query}" \
      -d '{}' 2>/dev/null || true)"
    http_code="$(tail -n1 <<<"${resp}")"
    if [[ "${http_code}" == "200" || "${http_code}" == "201" || "${http_code}" == "204" ]]; then
      installed_ok=1
      break
    fi

    # Some Fleet API versions reject specific query keys (force/ignoreUnverified).
    if grep -q '\[request query.force\]: definition for this key is missing' <<<"${resp}" 2>/dev/null; then
      continue
    fi
    if grep -q '\[request query.ignoreUnverified\]: definition for this key is missing' <<<"${resp}" 2>/dev/null; then
      continue
    fi

    status="$(get_package_status "${pkg}" || true)"
    if [[ "${status}" == "installed" ]]; then
      log "Package '${pkg}' reports installed despite install response HTTP ${http_code}; continuing."
      installed_ok=1
      break
    fi
  done

  if [[ "${installed_ok}" -ne 1 ]]; then
    log "Install package response body:"
    printf '%s\n' "${resp%$'\n'*}" >&2
    die "Failed installing package '${pkg}' (HTTP ${http_code})"
  fi

  printf '%s\n' "${ver}"
}

get_package_info_json_safe() {
  local pkg="$1"
  local resp
  if resp="$(kibana_get "/api/fleet/epm/packages/${pkg}" 2>/dev/null)"; then
    printf '%s\n' "${resp}"
    return 0
  fi
  return 1
}

package_policy_id_for_agent_policy_and_package() {
  local policy_id="$1"
  local package_name="$2"
  kibana_get '/api/fleet/package_policies?perPage=1000' | jq -r --arg pid "${policy_id}" --arg pkg "${package_name}" '
    .items[]
    | select(.policy_id == $pid and .package.name == $pkg)
    | .id
  ' | head -n1
}

fetch_package_policy_item() {
  local package_policy_id="$1"
  local suffix resp item payload
  local -a suffixes=(
    "?full=true"
    "?full=true&format=legacy"
    "?full=true&format=simplified"
  )

  for suffix in "${suffixes[@]}"; do
    if resp="$(kibana_get "/api/fleet/package_policies/${package_policy_id}${suffix}" 2>/dev/null)"; then
      item="$(jq -c '.item // empty' <<<"${resp}" 2>/dev/null || true)"
      if [[ -n "${item}" && "${item}" != "null" ]]; then
        printf '%s\n' "${item}"
        return 0
      fi
    fi
  done

  payload="$(jq -cn --arg id "${package_policy_id}" '{ids: [$id], ignoreMissing: true}')"
  for suffix in "" "?format=legacy" "?format=simplified"; do
    if resp="$(kibana_post_checked "/api/fleet/package_policies/_bulk_get${suffix}" "${payload}" 2>/dev/null)"; then
      item="$(jq -c '.items[0] // empty' <<<"${resp}" 2>/dev/null || true)"
      if [[ -n "${item}" && "${item}" != "null" ]]; then
        printf '%s\n' "${item}"
        return 0
      fi
    fi
  done

  return 1
}

build_generic_package_policy_payload_from_manifest() {
  local package_info="$1"
  local package_name="$2"
  local package_version="$3"
  local policy_id="$4"
  local integration_name="$5"
  jq -c \
    --arg name "${integration_name}" \
    --arg pid "${policy_id}" \
    --arg pkg "${package_name}" \
    --arg ver "${package_version}" '
      def stream_id($s):
        (($s.id // ($s.data_stream.dataset // $s.dataset // $s.title // $s.type // "stream")) | tostring | gsub("[^A-Za-z0-9._-]"; "_"));
      def policy_templates:
        (.item.policy_templates // .response[0].policy_templates // []);
      {
        name: $name,
        namespace: "default",
        policy_id: $pid,
        enabled: true,
        package: {
          name: $pkg,
          version: $ver
        },
        inputs: (
          [
            policy_templates[]?
            | select((.enabled // true) == true)
            | .inputs[]?
            | {
                type: (.type // .input // "log"),
                enabled: true,
                streams: (
                  [
                    (.streams // .data_streams // [])[]?
                    | {
                        id: stream_id(.),
                        enabled: true,
                        data_stream: (.data_stream // {
                          type: (.type // null),
                          dataset: (.dataset // null)
                        })
                      }
                  ]
                )
              }
          ]
        )
      }
      | .inputs |= map(if (.streams | length) == 0 then del(.streams) else . end)
      | if (.inputs | length) == 0 then del(.inputs) else . end
    ' <<<"${package_info}"
}

ensure_generic_integration_on_policy() {
  local policy_id="$1"
  local package_name="$2"
  local package_version="$3"
  local integration_name="$4"
  local required="${5:-true}"
  local existing
  existing="$(package_policy_id_for_agent_policy_and_package "${policy_id}" "${package_name}")"
  if [[ -n "${existing}" ]]; then
    log "Integration '${package_name}' already present on policy ${policy_id} (${existing})"
    printf '%s\n' "${existing}"
    return 0
  fi

  local payload resp package_info
  payload="$(jq -n \
    --arg name "${integration_name}" \
    --arg pid "${policy_id}" \
    --arg pkg "${package_name}" \
    --arg ver "${package_version}" \
    '{
      name: $name,
      namespace: "default",
      policy_id: $pid,
      enabled: true,
      package: {
        name: $pkg,
        version: $ver
      }
    }')"
  if resp="$(kibana_post_checked '/api/fleet/package_policies' "${payload}")"; then
    local created_id
    created_id="$(jq -r '.item.id // empty' <<<"${resp}")"
    if [[ -n "${created_id}" ]]; then
      printf '%s\n' "${created_id}"
      return 0
    fi
  fi

  package_info="$(get_package_info_json_safe "${package_name}" || true)"
  if [[ -n "${package_info}" ]]; then
    payload="$(build_generic_package_policy_payload_from_manifest "${package_info}" "${package_name}" "${package_version}" "${policy_id}" "${integration_name}")"
    if resp="$(kibana_post_checked '/api/fleet/package_policies' "${payload}")"; then
      local created_id
      created_id="$(jq -r '.item.id // empty' <<<"${resp}")"
      if [[ -n "${created_id}" ]]; then
        printf '%s\n' "${created_id}"
        return 0
      fi
    fi
  fi

  if [[ "${required}" == "true" ]]; then
    die "Failed to create '${package_name}' integration on policy ${policy_id}"
  fi
  log "Skipping '${package_name}' integration because creation failed and required=false"
  return 1
}

harden_windows_package_policy_streams() {
  local package_policy_id="$1"
  log "Enabling all streams in windows package policy ${package_policy_id}"
  local item payload updated summary
  local path
  local updated_ok=0

  item="$(fetch_package_policy_item "${package_policy_id}" || true)"
  [[ -n "${item}" && "${item}" != "null" ]] || die "Unable to fetch windows package policy for stream hardening"

  payload="$(jq -c '
    {
      name,
      description,
      namespace,
      policy_id,
      enabled,
      package,
      inputs,
      vars
    }
    | del(.. | nulls)
    | .inputs |= map(
        .enabled = true
        | if .streams then
            .streams |= map(.enabled = true)
          else
            .
          end
      )
  ' <<<"${item}")"

  for path in \
    "/api/fleet/package_policies/${package_policy_id}" \
    "/api/fleet/package_policies/${package_policy_id}?format=legacy" \
    "/api/fleet/package_policies/${package_policy_id}?format=simplified"; do
    if kibana_put_checked "${path}" "${payload}" >/dev/null; then
      updated_ok=1
      break
    fi
  done

  if [[ "${updated_ok}" -ne 1 ]]; then
    die "Failed to harden windows package policy streams"
  fi

  summary="$(fetch_package_policy_item "${package_policy_id}" | jq -c '
    . as $item
    | {
        total_streams: ([ $item.inputs[]?.streams[]? ] | length),
        enabled_streams: ([ $item.inputs[]?.streams[]? | select(.enabled == true) ] | length),
        sysmon_enabled: (
          [ $item.inputs[]?.streams[]? | select(((.id // .data_stream.dataset // "") | ascii_downcase | contains("sysmon")) and .enabled == true) ]
          | length
        )
      }
  ')"
  log "Windows integration summary: $(jq -c '.' <<<"${summary}")"
}

ensure_osquery_manager_integration() {
  local endpoint_policy_id="$1"
  if [[ "${ENABLE_OSQUERY_MANAGER}" != "true" ]]; then
    log "ENABLE_OSQUERY_MANAGER=false; skipping osquery manager integration"
    return 0
  fi

  local package_name="osquery_manager"
  if ! get_package_info_json_safe "${package_name}" >/dev/null; then
    die "Package '${package_name}' is not available from Fleet package registry"
  fi
  local package_version
  package_version="$(ensure_package_installed "${package_name}")"

  log "Ensuring osquery manager integration on endpoint policy"
  ensure_generic_integration_on_policy "${endpoint_policy_id}" "${package_name}" "${package_version}" "${OSQUERY_INTEGRATION_NAME}" "true" >/dev/null
}

ensure_windows_integration() {
  local endpoint_policy_id="$1"
  if [[ "${ENABLE_WINDOWS_INTEGRATION}" != "true" ]]; then
    log "ENABLE_WINDOWS_INTEGRATION=false; skipping windows telemetry integration"
    return 0
  fi

  local package_name="windows"
  if ! get_package_info_json_safe "${package_name}" >/dev/null; then
    die "Package '${package_name}' is not available from Fleet package registry"
  fi
  local package_version
  package_version="$(ensure_package_installed "${package_name}")"

  log "Ensuring windows telemetry integration on endpoint policy"
  local windows_pkg_policy_id
  windows_pkg_policy_id="$(ensure_generic_integration_on_policy "${endpoint_policy_id}" "${package_name}" "${package_version}" "${WINDOWS_INTEGRATION_NAME}" "true")"
  [[ -n "${windows_pkg_policy_id}" ]] || die "Windows integration returned empty package policy ID"
  harden_windows_package_policy_streams "${windows_pkg_policy_id}"
}

resolve_first_available_package_candidate() {
  local csv_candidates="$1"
  local raw candidate
  IFS=',' read -r -a raw <<<"${csv_candidates}"
  for candidate in "${raw[@]}"; do
    candidate="${candidate//[[:space:]]/}"
    [[ -n "${candidate}" ]] || continue
    if get_package_info_json_safe "${candidate}" >/dev/null; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

ensure_threat_intel_integration() {
  local fleet_server_policy_id="$1"
  if [[ "${ENABLE_THREAT_INTEL}" != "true" ]]; then
    log "ENABLE_THREAT_INTEL=false; skipping threat intel integration"
    return 0
  fi

  local package_name package_version raw candidate
  local attempted_any=0
  IFS=',' read -r -a raw <<<"${THREAT_INTEL_PACKAGE_CANDIDATES}"

  if [[ "${#raw[@]}" -eq 0 ]]; then
    if [[ "${REQUIRE_THREAT_INTEL}" == "true" ]]; then
      die "No threat intel package candidates available (${THREAT_INTEL_PACKAGE_CANDIDATES})"
    fi
    log "No threat intel package candidates available; skipping."
    return 0
  fi

  for candidate in "${raw[@]}"; do
    package_name="${candidate//[[:space:]]/}"
    [[ -n "${package_name}" ]] || continue
    if ! get_package_info_json_safe "${package_name}" >/dev/null; then
      continue
    fi

    attempted_any=1
    package_version="$(ensure_package_installed "${package_name}")"

    log "Ensuring threat intel integration (${package_name}) on Fleet Server policy"
    if ensure_generic_integration_on_policy \
        "${fleet_server_policy_id}" \
        "${package_name}" \
        "${package_version}" \
        "${THREAT_INTEL_INTEGRATION_NAME_PREFIX} (${package_name})" \
        "false"; then
      return 0
    fi

    log "Threat intel integration candidate '${package_name}' failed; trying next candidate if available."
  done

  if [[ "${attempted_any}" -eq 0 ]]; then
    if [[ "${REQUIRE_THREAT_INTEL}" == "true" ]]; then
      die "No threat intel package candidates available (${THREAT_INTEL_PACKAGE_CANDIDATES})"
    fi
    log "No threat intel package candidates available; skipping."
    return 0
  fi

  if [[ "${REQUIRE_THREAT_INTEL}" == "true" ]]; then
    die "Threat intel integration is required but all candidate installs failed"
  fi
  log "Threat intel integration failed in non-required mode; continuing."
}

agent_policy_id_by_name() {
  local name="$1"
  kibana_get '/api/fleet/agent_policies?perPage=1000' | jq -r --arg n "${name}" '
    .items[] | select(.name == $n) | .id
  ' | head -n1
}

fleet_server_policy_id_any() {
  kibana_get '/api/fleet/agent_policies?perPage=1000' | jq -r '
    .items[]
    | select(
        (.id == "fleet-server-policy")
        or
        (.is_default_fleet_server == true)
        or (.has_fleet_server == true)
        or ((.name // "" | ascii_downcase) | contains("fleet server"))
      )
    | .id
  ' | head -n1
}

create_agent_policy_with_variants() {
  local description="${1:-}"
  shift
  local resp="" path payload
  local -a path_variants=(
    '/api/fleet/agent_policies?sys_monitoring=true'
    '/api/fleet/agent_policies'
  )
  local -a payload_variants=( "$@" )

  for path in "${path_variants[@]}"; do
    for payload in "${payload_variants[@]}"; do
      if resp="$(kibana_post_checked "${path}" "${payload}")"; then
        printf '%s\n' "${resp}"
        return 0
      fi
    done
  done

  if [[ -n "${description}" ]]; then
    log "Agent policy creation exhausted all payload variants for ${description}"
  fi
  return 1
}

ensure_fleet_server_policy() {
  local existing
  existing="$(agent_policy_id_by_name "${FLEET_SERVER_POLICY_NAME}")"
  if [[ -n "${existing}" ]]; then
    log "Reusing Fleet Server agent policy: ${FLEET_SERVER_POLICY_NAME} (${existing})"
    printf '%s\n' "${existing}"
    return 0
  fi

  local any_fs
  any_fs="$(fleet_server_policy_id_any || true)"
  if [[ -n "${any_fs}" ]]; then
    log "Reusing existing Fleet Server policy (${any_fs})"
    printf '%s\n' "${any_fs}"
    return 0
  fi

  log "Creating Fleet Server agent policy"
  local payload resp
  local -a payload_variants=()
  payload_variants+=("$(jq -cn \
    --arg name "${FLEET_SERVER_POLICY_NAME}" \
    '{
      name: $name,
      namespace: "default",
      has_fleet_server: true,
      is_default_fleet_server: true
    }')")
  payload_variants+=("$(jq -cn \
    --arg name "${FLEET_SERVER_POLICY_NAME}" \
    '{
      name: $name,
      namespace: "default",
      description: "Fleet Server hosts for the lab",
      has_fleet_server: true,
      is_default_fleet_server: true
    }')")
  payload_variants+=("$(jq -cn \
    --arg name "${FLEET_SERVER_POLICY_NAME}" \
    '{
      name: $name,
      namespace: "default",
      monitoring_enabled: ["logs", "metrics"],
      has_fleet_server: true,
      is_default_fleet_server: true
    }')")
  payload_variants+=("$(jq -cn \
    --arg name "${FLEET_SERVER_POLICY_NAME}" \
    '{
      name: $name,
      namespace: "default",
      description: "Fleet Server hosts for the lab",
      monitoring_enabled: ["logs", "metrics"]
    }')")

  if ! resp="$(create_agent_policy_with_variants "Fleet Server policy" "${payload_variants[@]}")"; then
    # One more attempt to discover an auto-created default FS policy before failing.
    any_fs="$(fleet_server_policy_id_any || true)"
    if [[ -n "${any_fs}" ]]; then
      log "Discovered Fleet Server policy after create attempt (${any_fs})"
      printf '%s\n' "${any_fs}"
      return 0
    fi
    die "Failed to create Fleet Server agent policy"
  fi

  local id
  id="$(jq -r '.item.id // empty' <<<"${resp}")"
  [[ -n "${id}" ]] || die "Fleet Server policy create response missing item.id"
  printf '%s\n' "${id}"
}

ensure_fleet_server_package_policy() {
  local policy_id="$1"
  local fleet_server_pkg_version="$2"
  local existing
  existing="$(package_policy_id_for_agent_policy_and_package "${policy_id}" "fleet_server")"
  if [[ -n "${existing}" ]]; then
    log "Fleet Server integration already present on policy ${policy_id} (${existing})"
    printf '%s\n' "${existing}"
    return 0
  fi

  log "Ensuring Fleet Server integration is attached to policy ${policy_id}"
  ensure_generic_integration_on_policy \
    "${policy_id}" \
    "fleet_server" \
    "${fleet_server_pkg_version}" \
    "Fleet Server - GOAD" \
    "true"
}

ensure_endpoint_agent_policy() {
  local existing
  existing="$(agent_policy_id_by_name "${ENDPOINT_POLICY_NAME}")"
  if [[ -n "${existing}" ]]; then
    log "Reusing endpoint agent policy: ${ENDPOINT_POLICY_NAME} (${existing})"
    printf '%s\n' "${existing}"
    return 0
  fi

  log "Creating endpoint agent policy"
  local resp
  if ! resp="$(create_agent_policy_with_variants "endpoint agent policy" \
    "$(jq -cn --arg name "${ENDPOINT_POLICY_NAME}" '{
      name: $name,
      namespace: "default",
      description: "GOAD lab Windows endpoints for EDR testing"
    }')" \
    "$(jq -cn --arg name "${ENDPOINT_POLICY_NAME}" '{
      name: $name,
      namespace: "default",
      monitoring_enabled: ["logs", "metrics"],
      description: "GOAD lab Windows endpoints for EDR testing"
    }')")"; then
    die "Failed to create endpoint agent policy"
  fi

  local id
  id="$(jq -r '.item.id // empty' <<<"${resp}")"
  [[ -n "${id}" ]] || die "Endpoint policy create response missing item.id"
  printf '%s\n' "${id}"
}

endpoint_package_policy_id_for_agent_policy() {
  local policy_id="$1"
  kibana_get '/api/fleet/package_policies?perPage=1000' | jq -r --arg pid "${policy_id}" '
    .items[]
    | select(.policy_id == $pid and .package.name == "endpoint")
    | .id
  ' | head -n1
}

ensure_endpoint_defend_integration() {
  local policy_id="$1"
  local endpoint_pkg_version="$2"
  local existing
  LAST_ENDPOINT_PACKAGE_POLICY_ITEM=""
  existing="$(endpoint_package_policy_id_for_agent_policy "${policy_id}")"
  if [[ -n "${existing}" ]]; then
    log "Endpoint integration already present on policy ${policy_id} (${existing})"
    LAST_ENDPOINT_PACKAGE_POLICY_ITEM="$(fetch_package_policy_item "${existing}" || true)"
    printf '%s\n' "${existing}"
    return 0
  fi

  log "Creating Elastic Defend integration on endpoint policy (${endpoint_pkg_version}, preset=EDRComplete)"
  local payload resp
  local -a payload_variants=()
  payload_variants+=("$(jq -cn \
    --arg name "${ENDPOINT_INTEGRATION_NAME}" \
    --arg pid "${policy_id}" \
    --arg ver "${endpoint_pkg_version}" \
    '{
      name: $name,
      description: "",
      namespace: "default",
      policy_id: $pid,
      enabled: true,
      package: {
        name: "endpoint",
        title: "Elastic Defend",
        version: $ver
      },
      inputs: [
        {
          type: "ENDPOINT_INTEGRATION_CONFIG",
          enabled: true,
          streams: [],
          config: {
            _config: {
              value: {
                type: "endpoint",
                endpointConfig: {
                  preset: "EDRComplete"
                }
              }
            }
          }
        }
      ]
    }')")
  payload_variants+=("$(jq -cn \
    --arg name "${ENDPOINT_INTEGRATION_NAME}" \
    --arg pid "${policy_id}" \
    --arg ver "${endpoint_pkg_version}" \
    '{
      name: $name,
      namespace: "default",
      policy_id: $pid,
      enabled: true,
      package: {
        name: "endpoint",
        version: $ver
      },
      inputs: [
        {
          enabled: true,
          streams: [],
          type: "endpoint"
        }
      ]
    }')")
  payload_variants+=("$(jq -cn \
    --arg name "${ENDPOINT_INTEGRATION_NAME}" \
    --arg pid "${policy_id}" \
    --arg ver "${endpoint_pkg_version}" \
    '{
      name: $name,
      namespace: "default",
      policy_id: $pid,
      enabled: true,
      package: {
        name: "endpoint",
        version: $ver
      }
    }')")

  local created=0
  for payload in "${payload_variants[@]}"; do
    if resp="$(kibana_post_checked '/api/fleet/package_policies' "${payload}")"; then
      created=1
      break
    fi
  done
  if [[ "${created}" -ne 1 ]]; then
    # Last chance: return existing package policy if one was created concurrently.
    existing="$(endpoint_package_policy_id_for_agent_policy "${policy_id}" || true)"
    if [[ -n "${existing}" ]]; then
      log "Endpoint integration discovered after create attempts (${existing})"
      printf '%s\n' "${existing}"
      return 0
    fi
    die "Failed to create Elastic Defend package policy"
  fi

  local id
  id="$(jq -r '.item.id // empty' <<<"${resp}")"
  [[ -n "${id}" ]] || die "Elastic Defend package policy response missing item.id"
  LAST_ENDPOINT_PACKAGE_POLICY_ITEM="$(jq -c '.item // empty' <<<"${resp}" 2>/dev/null || true)"
  printf '%s\n' "${id}"
}

build_hardened_endpoint_policy_payload() {
  local raw_item="$1"
  local disable_lsass_json="false"
  if [[ "${DISABLE_WINDOWS_LSASS_PROTECTION}" == "true" ]]; then
    disable_lsass_json="true"
  fi
  jq -c --argjson disable_lsass "${disable_lsass_json}" '
    def set_path($path; $value):
      setpath($path; $value);
    {
      name,
      description,
      namespace,
      policy_id,
      enabled,
      package,
      inputs,
      vars
    }
    | del(.. | nulls)
    | .inputs |= (
        map(
          if (.config?._config?.value?.endpointConfig?.preset? // "") != "" then
            .config._config.value.endpointConfig.preset = "EDRComplete"
          else
            .
          end
          | if (.config?.integration_config?.value?.endpointConfig?.preset? // "") != "" then
              .config.integration_config.value.endpointConfig.preset = "EDRComplete"
            else
              .
            end
          | .config.policy.value |= (
              (. // {})
              | set_path(["windows","malware","mode"]; "prevent")
              | set_path(["windows","ransomware","mode"]; "prevent")
              | set_path(["windows","memory_protection","mode"]; "prevent")
              | set_path(["windows","behavior_protection","mode"]; "prevent")
              | set_path(["windows","attack_surface_reduction","credential_hardening","enabled"]; (if $disable_lsass then false else true end))
              | set_path(["windows","credential_hardening","enabled"]; (if $disable_lsass then false else true end))
              | set_path(["windows","popup","malware","enabled"]; true)
              | set_path(["windows","popup","ransomware","enabled"]; true)
              | set_path(["windows","popup","memory_protection","enabled"]; true)
              | set_path(["windows","popup","behavior_protection","enabled"]; true)
              | set_path(["linux","malware","mode"]; "prevent")
              | set_path(["linux","memory_protection","mode"]; "prevent")
              | set_path(["linux","behavior_protection","mode"]; "prevent")
              | set_path(["mac","malware","mode"]; "prevent")
              | set_path(["mac","ransomware","mode"]; "prevent")
              | set_path(["mac","memory_protection","mode"]; "prevent")
              | set_path(["mac","behavior_protection","mode"]; "prevent")
              | set_path(["mac","popup","malware","enabled"]; true)
              | set_path(["mac","popup","ransomware","enabled"]; true)
              | set_path(["mac","popup","memory_protection","enabled"]; true)
              | set_path(["mac","popup","behavior_protection","enabled"]; true)
            )
        )
      )
  ' <<<"${raw_item}"
}

summarize_endpoint_hardening() {
  local endpoint_package_policy_id="$1"
  local item summary
  item="$(fetch_package_policy_item "${endpoint_package_policy_id}" || true)"
  [[ -n "${item}" && "${item}" != "null" ]] || {
    printf '{"preset":"","prevent_modes":0,"credential_hardening_enabled":0,"credential_hardening_disabled":0}\n'
    return 0
  }

  summary="$(jq -c '
    .item as $item
    | {
        preset: (
          [
            $item.inputs[]?.config?._config?.value?.endpointConfig?.preset,
            $item.inputs[]?.config?.integration_config?.value?.endpointConfig?.preset
          ]
          | map(select(type == "string"))
          | first // ""
        ),
        prevent_modes: (
          [
            $item.inputs[]?.config?.policy?.value?.windows?.malware?.mode,
            $item.inputs[]?.config?.policy?.value?.windows?.ransomware?.mode,
            $item.inputs[]?.config?.policy?.value?.windows?.memory_protection?.mode,
            $item.inputs[]?.config?.policy?.value?.windows?.behavior_protection?.mode,
            $item.inputs[]?.config?.policy?.value?.linux?.malware?.mode,
            $item.inputs[]?.config?.policy?.value?.linux?.memory_protection?.mode,
            $item.inputs[]?.config?.policy?.value?.linux?.behavior_protection?.mode,
            $item.inputs[]?.config?.policy?.value?.mac?.malware?.mode,
            $item.inputs[]?.config?.policy?.value?.mac?.ransomware?.mode,
            $item.inputs[]?.config?.policy?.value?.mac?.memory_protection?.mode,
            $item.inputs[]?.config?.policy?.value?.mac?.behavior_protection?.mode
          ]
          | map(select(type == "string"))
          | map(select(ascii_downcase == "prevent"))
          | length
        ),
        credential_hardening_enabled: (
          [
            $item.inputs[]?.config?.policy?.value?.windows?.credential_hardening?.enabled,
            $item.inputs[]?.config?.policy?.value?.windows?.attack_surface_reduction?.credential_hardening?.enabled
          ]
          | map(select(. == true))
          | length
        ),
        credential_hardening_disabled: (
          [
            $item.inputs[]?.config?.policy?.value?.windows?.credential_hardening?.enabled,
            $item.inputs[]?.config?.policy?.value?.windows?.attack_surface_reduction?.credential_hardening?.enabled
          ]
          | map(select(. == false))
          | length
        )
      }
  ' <<<"{\"item\":${item}}")"
  printf '%s\n' "${summary}"
}

apply_endpoint_hardening() {
  local endpoint_package_policy_id="$1"
  local source_item="${2:-}"
  if [[ "${ENFORCE_ENDPOINT_HARDENING}" != "true" ]]; then
    log "ENFORCE_ENDPOINT_HARDENING=false; skipping endpoint hardening pass"
    return 0
  fi

  log "Applying hardened Elastic Defend settings to package policy ${endpoint_package_policy_id}"
  local item payload resp
  local updated=0
  local path

  item="${source_item}"
  if [[ -z "${item}" || "${item}" == "null" ]]; then
    item="$(fetch_package_policy_item "${endpoint_package_policy_id}" || true)"
  fi
  [[ -n "${item}" && "${item}" != "null" ]] || die "Unable to fetch endpoint package policy item for hardening. Elastic returned item=null for package policy ${endpoint_package_policy_id}."
  payload="$(build_hardened_endpoint_policy_payload "${item}")"
  [[ -n "${payload}" ]] || die "Failed to build hardened endpoint package policy payload"

  for path in \
    "/api/fleet/package_policies/${endpoint_package_policy_id}" \
    "/api/fleet/package_policies/${endpoint_package_policy_id}?format=legacy" \
    "/api/fleet/package_policies/${endpoint_package_policy_id}?format=simplified"; do
    if resp="$(kibana_put_checked "${path}" "${payload}")"; then
      updated=1
      break
    fi
  done

  if [[ "${updated}" -ne 1 ]]; then
    die "Failed to apply endpoint hardening settings"
  fi

  local summary preset prevent_count credential_count credential_disabled_count post_item
  post_item="$(jq -c '.item // empty' <<<"${resp}" 2>/dev/null || true)"
  if [[ -z "${post_item}" || "${post_item}" == "null" ]]; then
    post_item="$(fetch_package_policy_item "${endpoint_package_policy_id}" || true)"
  fi
  if [[ -n "${post_item}" && "${post_item}" != "null" ]]; then
    summary="$(jq -c '
      . as $item
      | {
          preset: (
            [
              $item.inputs[]?.config?._config?.value?.endpointConfig?.preset,
              $item.inputs[]?.config?.integration_config?.value?.endpointConfig?.preset
            ]
            | map(select(type == "string"))
            | first // ""
          ),
          prevent_modes: (
            [
              $item.inputs[]?.config?.policy?.value?.windows?.malware?.mode,
              $item.inputs[]?.config?.policy?.value?.windows?.ransomware?.mode,
              $item.inputs[]?.config?.policy?.value?.windows?.memory_protection?.mode,
              $item.inputs[]?.config?.policy?.value?.windows?.behavior_protection?.mode,
              $item.inputs[]?.config?.policy?.value?.linux?.malware?.mode,
              $item.inputs[]?.config?.policy?.value?.linux?.memory_protection?.mode,
              $item.inputs[]?.config?.policy?.value?.linux?.behavior_protection?.mode,
              $item.inputs[]?.config?.policy?.value?.mac?.malware?.mode,
              $item.inputs[]?.config?.policy?.value?.mac?.ransomware?.mode,
              $item.inputs[]?.config?.policy?.value?.mac?.memory_protection?.mode,
              $item.inputs[]?.config?.policy?.value?.mac?.behavior_protection?.mode
            ]
            | map(select(type == "string"))
            | map(select(ascii_downcase == "prevent"))
            | length
          ),
          credential_hardening_enabled: (
            [
              $item.inputs[]?.config?.policy?.value?.windows?.credential_hardening?.enabled,
              $item.inputs[]?.config?.policy?.value?.windows?.attack_surface_reduction?.credential_hardening?.enabled
            ]
            | map(select(. == true))
            | length
          ),
          credential_hardening_disabled: (
            [
              $item.inputs[]?.config?.policy?.value?.windows?.credential_hardening?.enabled,
              $item.inputs[]?.config?.policy?.value?.windows?.attack_surface_reduction?.credential_hardening?.enabled
            ]
            | map(select(. == false))
            | length
          )
        }
    ' <<<"${post_item}")"
    preset="$(jq -r '.preset // ""' <<<"${summary}")"
    prevent_count="$(jq -r '.prevent_modes // 0' <<<"${summary}")"
    credential_count="$(jq -r '.credential_hardening_enabled // 0' <<<"${summary}")"
    credential_disabled_count="$(jq -r '.credential_hardening_disabled // 0' <<<"${summary}")"
    log "Endpoint hardening summary: preset=${preset:-<none>} prevent_modes=${prevent_count} credential_hardening_enabled_matches=${credential_count} credential_hardening_disabled_matches=${credential_disabled_count} disable_lsass=${DISABLE_WINDOWS_LSASS_PROTECTION}"

    if [[ "${preset}" != "EDRComplete" && "${prevent_count}" -eq 0 ]]; then
      die "Endpoint hardening verification failed: no EDRComplete preset and no prevent-mode protections detected"
    fi
  else
    log "Endpoint hardening update succeeded, but Elastic still returned item=null when refetching package policy ${endpoint_package_policy_id}; skipping post-update summary."
  fi
}

install_prebuilt_detection_rules() {
  if [[ "${ENABLE_PREBUILT_RULES}" != "true" ]]; then
    log "ENABLE_PREBUILT_RULES=false; skipping prebuilt detection rule install"
    return 0
  fi

  log "Initializing Elastic Security detection engine"
  if ! kibana_post_checked '/api/detection_engine/index' '{}' >/dev/null 2>&1; then
    log "Detection engine index init call returned non-success; continuing."
  fi

  log "Installing/updating prebuilt detection rules"
  local installed=0
  if kibana_put_checked '/api/detection_engine/rules/prepackaged' '{}' >/dev/null 2>&1; then
    installed=1
  elif kibana_post_checked '/api/detection_engine/rules/prepackaged' '{}' >/dev/null 2>&1; then
    installed=1
  fi

  if [[ "${installed}" -ne 1 ]]; then
    log "Prebuilt rule install API did not return success. Install manually from Security -> Rules if needed."
    return 0
  fi

  log "Enabling immutable prebuilt rules (best effort)"
  if ! kibana_post_checked '/api/detection_engine/rules/_bulk_action' '{"action":"enable","query":"alert.attributes.immutable: true"}' >/dev/null 2>&1; then
    log "Bulk enable for prebuilt rules did not return success; leaving rule state unchanged."
  fi
}

create_fleet_service_token() {
  local token_name="goad-fleet-server-$(date +%Y%m%d%H%M%S)"
  local resp
  resp="$(curl -sS -u "elastic:${ELASTIC_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -X POST "${ES_URL_LOCAL}/_security/service/elastic/fleet-server/credential/token/${token_name}")" || {
      die "Failed to create Elasticsearch service token for Fleet Server"
    }

  local token
  token="$(jq -r '.token.value // empty' <<<"${resp}")"
  [[ -n "${token}" ]] || die "Fleet service token response missing token.value"
  printf '%s\n' "${token}"
}

start_or_replace_fleet_server_container() {
  local fleet_server_policy_id="$1"
  local fleet_service_token="$2"
  local compose_network="${COMPOSE_PROJECT}_default"

  docker volume create "${FLEET_SERVER_STATE_VOLUME}" >/dev/null
  docker rm -f "${FLEET_SERVER_CONTAINER}" >/dev/null 2>&1 || true

  log "Starting Fleet Server container (${FLEET_SERVER_CONTAINER})"
  docker run -d \
    --name "${FLEET_SERVER_CONTAINER}" \
    --restart unless-stopped \
    --network "${compose_network}" \
    -p "${FLEET_SERVER_PORT}:8220" \
    -u root \
    -v "${FLEET_SERVER_STATE_VOLUME}:/usr/share/elastic-agent/state" \
    -e FLEET_SERVER_ENABLE=true \
    -e FLEET_SERVER_INSECURE_HTTP=true \
    -e FLEET_SERVER_HOST=0.0.0.0 \
    -e FLEET_SERVER_PORT=8220 \
    -e FLEET_SERVER_ELASTICSEARCH_HOST=http://es01:9200 \
    -e FLEET_SERVER_POLICY_ID="${fleet_server_policy_id}" \
    -e FLEET_SERVER_SERVICE_TOKEN="${fleet_service_token}" \
    -e FLEET_URL="${FLEET_PUBLIC_URL}" \
    "docker.elastic.co/elastic-agent/elastic-agent:${STACK_VERSION}" >/dev/null
}

ensure_fleet_server_runtime() {
  local fleet_server_policy_id="$1"
  local fleet_service_token="$2"

  if fleet_server_is_healthy "${FLEET_PUBLIC_URL}"; then
    log "Fleet Server already healthy at ${FLEET_PUBLIC_URL}; reusing existing deployment"
    return 0
  fi

  case "${FLEET_SERVER_MODE}" in
    external)
      log "FLEET_SERVER_MODE=external; skipping container start. Use ${OUTPUT_DIR}/fleet-server-install-example.sh if you want a host-installed Fleet Server."
      return 0
      ;;
    auto|container)
      ;;
    *)
      die "Unsupported FLEET_SERVER_MODE='${FLEET_SERVER_MODE}'. Use auto, container, or external."
      ;;
  esac

  if host_port_in_use "${FLEET_SERVER_PORT}" && ! docker inspect "${FLEET_SERVER_CONTAINER}" >/dev/null 2>&1; then
    die "Port ${FLEET_SERVER_PORT} is already in use. If that is your manual Fleet Server, set FLEET_SERVER_MODE=external. Otherwise free the port and rerun."
  fi

  start_or_replace_fleet_server_container "${fleet_server_policy_id}" "${fleet_service_token}"
  wait_for_fleet_server "http://127.0.0.1:${FLEET_SERVER_PORT}" "true"
}

create_enrollment_api_key() {
  local policy_id="$1"
  local key_name="${ENROLLMENT_KEY_NAME}-$(date +%Y%m%d%H%M%S)"
  local payload resp key
  local -a payload_variants=(
    "$(jq -cn --arg name "${key_name}" --arg pid "${policy_id}" '{name: $name, policy_id: $pid}')"
    "$(jq -cn --arg pid "${policy_id}" '{policy_id: $pid}')"
  )

  for payload in "${payload_variants[@]}"; do
    if resp="$(kibana_post_checked '/api/fleet/enrollment_api_keys' "${payload}")"; then
      key="$(jq -r '.item.api_key // empty' <<<"${resp}")"
      if [[ -n "${key}" ]]; then
        printf '%s\n' "${key}"
        return 0
      fi
    fi
  done

  key="$(kibana_get '/api/fleet/enrollment_api_keys?perPage=1000' \
    | jq -r --arg pid "${policy_id}" 'first(.list[]? | select(.policy_id==$pid and .active==true) | .api_key) // empty')"
  if [[ -n "${key}" ]]; then
    log "Reusing existing active enrollment key for policy ${policy_id}"
    printf '%s\n' "${key}"
    return 0
  fi

  die "Failed to create Fleet enrollment API key"
}

agent_archive_suffix() {
  local platform="$1"
  local arch="$2"
  case "${platform}:${arch}" in
    linux:x86_64) printf 'linux-x86_64\n' ;;
    linux:arm64) printf 'linux-arm64\n' ;;
    macos:x86_64) printf 'darwin-x86_64\n' ;;
    macos:arm64) printf 'darwin-aarch64\n' ;;
    *)
      return 1
      ;;
  esac
}

print_agent_enrollment_command() {
  local platform="$1"
  local arch="$2"
  local enrollment_token="$3"
  local suffix archive

  case "${platform}:${arch}" in
    windows:x86_64)
      cat <<EOFOUT
Set-ExecutionPolicy -Scope Process Bypass -Force
.\\Enroll-ElasticAgent.ps1 -FleetUrl '${FLEET_PUBLIC_URL}' -EnrollmentToken '${enrollment_token}' -AgentVersion '${STACK_VERSION}' -Insecure -InstallSysmon
EOFOUT
      return 0
      ;;
  esac

  suffix="$(agent_archive_suffix "${platform}" "${arch}")" || die "Unsupported enrollment target ${platform}/${arch}"
  archive="elastic-agent-${STACK_VERSION}-${suffix}.tar.gz"
  cat <<EOFOUT
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/${archive}
tar xzvf ${archive}
cd elastic-agent-${STACK_VERSION}-${suffix}
sudo ./elastic-agent install --url='${FLEET_PUBLIC_URL}' --enrollment-token='${enrollment_token}' --insecure
EOFOUT
}

write_fleet_server_install_example() {
  local fleet_server_policy_id="$1"
  local fleet_service_token="$2"
  cat > "${OUTPUT_DIR}/fleet-server-install-example.sh" <<EOFOUT
#!/usr/bin/env bash
set -euo pipefail

curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${STACK_VERSION}-linux-x86_64.tar.gz
tar xzvf elastic-agent-${STACK_VERSION}-linux-x86_64.tar.gz
cd elastic-agent-${STACK_VERSION}-linux-x86_64
sudo ./elastic-agent install \\
  --fleet-server-es='${ELASTIC_PUBLIC_URL}' \\
  --fleet-server-service-token='${fleet_service_token}' \\
  --fleet-server-policy='${fleet_server_policy_id}' \\
  --fleet-server-port='${FLEET_SERVER_PORT}' \\
  --fleet-server-insecure-http \\
  --install-servers
EOFOUT
  chmod 700 "${OUTPUT_DIR}/fleet-server-install-example.sh"
}

write_agent_enrollment_examples() {
  local enrollment_token="$1"

  cat > "${OUTPUT_DIR}/windows-enroll-example.txt" <<EOFOUT
# PowerShell (admin) on each Windows host:
$(print_agent_enrollment_command windows x86_64 "${enrollment_token}")
EOFOUT

  cat > "${OUTPUT_DIR}/linux-enroll-example.sh" <<EOFOUT
#!/usr/bin/env bash
set -euo pipefail
$(print_agent_enrollment_command linux x86_64 "${enrollment_token}")
EOFOUT
  chmod 700 "${OUTPUT_DIR}/linux-enroll-example.sh"

  cat > "${OUTPUT_DIR}/linux-arm64-enroll-example.sh" <<EOFOUT
#!/usr/bin/env bash
set -euo pipefail
$(print_agent_enrollment_command linux arm64 "${enrollment_token}")
EOFOUT
  chmod 700 "${OUTPUT_DIR}/linux-arm64-enroll-example.sh"

  cat > "${OUTPUT_DIR}/macos-enroll-example.sh" <<EOFOUT
#!/usr/bin/env bash
set -euo pipefail
$(print_agent_enrollment_command macos x86_64 "${enrollment_token}")
EOFOUT
  chmod 700 "${OUTPUT_DIR}/macos-enroll-example.sh"

  cat > "${OUTPUT_DIR}/macos-arm64-enroll-example.sh" <<EOFOUT
#!/usr/bin/env bash
set -euo pipefail
$(print_agent_enrollment_command macos arm64 "${enrollment_token}")
EOFOUT
  chmod 700 "${OUTPUT_DIR}/macos-arm64-enroll-example.sh"
}

write_windows_enrollment_script() {
  cat > "${OUTPUT_DIR}/Enroll-ElasticAgent.ps1" <<'EOFOUT'
[CmdletBinding()]
param(
    [string]$FleetUrl = '',
    [string]$EnrollmentToken = '',

    [string]$AgentVersion = '9.2.3',
    [string]$DownloadDir = "$env:TEMP\elastic-agent",
    [switch]$Insecure,
    [switch]$InstallSysmon,
    [string]$SysmonConfigUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',
    [switch]$ForceReinstall,
    [switch]$UninstallOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Wait-ServiceRunning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [int]$TimeoutSeconds = 90
    )

    $sw = [Diagnostics.Stopwatch]::StartNew()
    do {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            return $true
        }
        Start-Sleep -Seconds 3
    } while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds)

    return $false
}

function Download-File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [Parameter(Mandatory = $true)]
        [string]$OutFile
    )

    Remove-Item -Path $OutFile -Force -ErrorAction SilentlyContinue

    if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
        try {
            Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
            return
        } catch {
            Write-Warning "BITS download failed, falling back to Invoke-WebRequest: $($_.Exception.Message)"
        }
    }

    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
}

function Test-MsiHeader {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $expected = 'D0-CF-11-E0-A1-B1-1A-E1'
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $bytes = New-Object byte[] 8
        [void]$fs.Read($bytes, 0, 8)
    } finally {
        $fs.Dispose()
    }

    $actual = [BitConverter]::ToString($bytes)
    return $actual -eq $expected
}

function Install-Sysmon {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseDownloadDir,
        [string]$ConfigUrl = ''
    )

    $sysmonRoot = Join-Path $BaseDownloadDir 'sysmon'
    $zipPath = Join-Path $sysmonRoot 'Sysmon.zip'
    $extractDir = Join-Path $sysmonRoot 'extracted'
    $sysmonExe = Join-Path $extractDir 'Sysmon64.exe'
    $configPath = Join-Path $sysmonRoot 'sysmon-config.xml'

    New-Item -ItemType Directory -Path $sysmonRoot -Force | Out-Null
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $configPath -Force -ErrorAction SilentlyContinue

    Download-File -Url 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
    if (-not (Test-Path $sysmonExe)) {
        throw "Sysmon64.exe not found after extraction: $sysmonExe"
    }

    $hasConfig = $false
    if (-not [string]::IsNullOrWhiteSpace($ConfigUrl)) {
        try {
            Download-File -Url $ConfigUrl -OutFile $configPath
            $hasConfig = (Test-Path $configPath)
        } catch {
            Write-Warning "Failed to download Sysmon config from $ConfigUrl. Continuing with default Sysmon config."
            $hasConfig = $false
        }
    }

    $sysmonService = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if ($sysmonService) {
        if ($hasConfig) {
            & $sysmonExe -accepteula -c $configPath | Out-Host
        } else {
            Write-Host 'Sysmon already installed. No config update was applied.'
        }
    } else {
        if ($hasConfig) {
            & $sysmonExe -accepteula -i $configPath | Out-Host
        } else {
            & $sysmonExe -accepteula -i | Out-Host
        }
    }
}

function Invoke-ElasticAgentUninstall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AgentExe,
        [int]$TimeoutSeconds = 120
    )

    if (-not (Test-Path $AgentExe)) {
        return $false
    }

    try {
        $proc = Start-Process -FilePath $AgentExe -ArgumentList @('uninstall', '-f') -PassThru
    } catch {
        Write-Warning "Failed to launch elastic-agent uninstall: $($_.Exception.Message)"
        return $false
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (-not $proc.HasExited -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        Start-Sleep -Seconds 2
    }

    if (-not $proc.HasExited) {
        Write-Warning "elastic-agent uninstall timed out after $TimeoutSeconds seconds. Killing process."
        try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop } catch {}
        return $false
    }

    if ($proc.ExitCode -eq 0) {
        return $true
    }

    Write-Warning "elastic-agent uninstall exited with code $($proc.ExitCode)"
    return $false
}

function Get-ElasticAgentProductCode {
    $keys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $items = foreach ($k in $keys) {
        Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    }

    $hit = $items | Where-Object { $_.DisplayName -like 'Elastic Agent*' } | Select-Object -First 1
    if (-not $hit) {
        return ''
    }

    if ($hit.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') {
        return $hit.PSChildName
    }

    if ($hit.UninstallString -match '\{[0-9A-Fa-f-]{36}\}') {
        return $matches[0]
    }

    return ''
}

function Invoke-MsiUninstallByProductCode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProductCode,
        [Parameter(Mandatory = $true)]
        [string]$LogDir
    )

    if ([string]::IsNullOrWhiteSpace($ProductCode)) {
        return $false
    }

    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    $msiLog = Join-Path $LogDir 'elastic-agent-msi-uninstall.log'
    $args = @('/x', $ProductCode, '/qn', '/norestart', '/L*v', $msiLog)
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -PassThru

    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 1605) {
        return $true
    }

    Write-Warning "msiexec uninstall failed with exit code $($proc.ExitCode). See $msiLog"
    return $false
}

function Force-CleanupElasticAgent {
    Write-Host 'Forcing cleanup of Elastic Agent service/process/files...'

    $svc = Get-Service -Name 'Elastic Agent' -ErrorAction SilentlyContinue
    if ($svc) {
        try { Stop-Service -Name 'Elastic Agent' -Force -ErrorAction Stop } catch {}
    }

    Get-Process -Name 'elastic-agent' -ErrorAction SilentlyContinue | ForEach-Object {
        try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {}
    }

    & sc.exe delete 'Elastic Agent' | Out-Null

    $paths = @(
        (Join-Path $env:ProgramFiles 'Elastic\Agent'),
        (Join-Path $env:ProgramData 'Elastic\Agent')
    )
    foreach ($p in $paths) {
        Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Remove-ElasticAgentRobust {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AgentExe,
        [Parameter(Mandatory = $true)]
        [string]$LogDir
    )

    $ok = $false
    if (Invoke-ElasticAgentUninstall -AgentExe $AgentExe -TimeoutSeconds 120) {
        $ok = $true
    }

    $productCode = Get-ElasticAgentProductCode
    if (-not [string]::IsNullOrWhiteSpace($productCode)) {
        if (Invoke-MsiUninstallByProductCode -ProductCode $productCode -LogDir $LogDir) {
            $ok = $true
        }
    }

    Force-CleanupElasticAgent
    return $ok
}

if (-not (Test-IsAdministrator)) {
    throw 'Run this script from an elevated PowerShell session (Run as Administrator).'
}

New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null

$agentExe = Join-Path $env:ProgramFiles 'Elastic\Agent\elastic-agent.exe'
$svc = Get-Service -Name 'Elastic Agent' -ErrorAction SilentlyContinue

if ($svc -and -not $ForceReinstall) {
    if ($UninstallOnly) {
        Write-Host 'UninstallOnly specified. Removing Elastic Agent...'
        [void](Remove-ElasticAgentRobust -AgentExe $agentExe -LogDir $DownloadDir)
        Write-Host 'Elastic Agent uninstall/cleanup completed.'
        return
    }
    Write-Host "Elastic Agent is already installed (service status: $($svc.Status)). Use -ForceReinstall to replace it."
    if (Test-Path $agentExe) {
        & $agentExe status
    }
    return
}

if ($UninstallOnly -and -not $svc) {
    Write-Host 'Elastic Agent is not currently installed.'
    return
}

if (-not $UninstallOnly) {
    if ([string]::IsNullOrWhiteSpace($FleetUrl)) {
        throw 'FleetUrl is required unless -UninstallOnly is used.'
    }
    if ([string]::IsNullOrWhiteSpace($EnrollmentToken)) {
        throw 'EnrollmentToken is required unless -UninstallOnly is used.'
    }
}

if ($svc -and $ForceReinstall) {
    Write-Host 'Force reinstall requested. Attempting uninstall first...'
    [void](Remove-ElasticAgentRobust -AgentExe $agentExe -LogDir $DownloadDir)
    Start-Sleep -Seconds 5
}

$msiName = "elastic-agent-$AgentVersion-windows-x86_64.msi"
$msiPath = Join-Path $DownloadDir $msiName
$msiUrl = "https://artifacts.elastic.co/downloads/beats/elastic-agent/$msiName"

Write-Host "Downloading $msiUrl"
Download-File -Url $msiUrl -OutFile $msiPath

if (-not (Test-Path $msiPath)) {
    throw "MSI download failed: $msiPath was not created."
}

$msiFile = Get-Item $msiPath
if ($msiFile.Length -lt 100MB) {
    throw "Downloaded MSI is unexpectedly small ($($msiFile.Length) bytes). Usually this means proxy/captive-portal content instead of the installer."
}

if (-not (Test-MsiHeader -Path $msiPath)) {
    throw 'Downloaded file does not appear to be a valid MSI (header mismatch).'
}

Unblock-File -Path $msiPath -ErrorAction SilentlyContinue

$installArgs = @(
    "--url=$FleetUrl",
    "--enrollment-token=$EnrollmentToken"
)

if ($Insecure) {
    $installArgs += '--insecure'
}

$installArgsString = ($installArgs -join ' ')
$msiExecArgs = @(
    '/i',
    "`"$msiPath`"",
    "INSTALLARGS=`"$installArgsString`"",
    '/qn',
    '/norestart',
    '/L*v',
    "`"$DownloadDir\elastic-agent-msi.log`""
)

Write-Host 'Installing and enrolling Elastic Agent...'
$proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiExecArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    if ($proc.ExitCode -eq 1620) {
        throw "msiexec failed with 1620 (invalid/unopenable MSI). Check $DownloadDir\elastic-agent-msi.log and verify network/proxy did not alter the download."
    }
    throw "msiexec.exe failed with exit code $($proc.ExitCode). See $DownloadDir\elastic-agent-msi.log"
}

if (-not (Wait-ServiceRunning -Name 'Elastic Agent' -TimeoutSeconds 120)) {
    throw 'Elastic Agent service did not reach Running state in time.'
}

if ($InstallSysmon) {
    try {
        Write-Host 'Installing Sysmon for enhanced Windows telemetry...'
        Install-Sysmon -BaseDownloadDir $DownloadDir -ConfigUrl $SysmonConfigUrl
    } catch {
        Write-Warning "Sysmon install/update failed: $($_.Exception.Message)"
    }
}

Write-Host 'Elastic Agent installed and service is running.'
if (Test-Path $agentExe) {
    & $agentExe status
}
EOFOUT
}

write_outputs() {
  local endpoint_policy_id="$1"
  local endpoint_package_policy_id="$2"
  local endpoint_enrollment_token="$3"
  local endpoint_pkg_version="$4"
  local fleet_server_policy_id="${5:-}"
  local fleet_service_token="${6:-}"

  mkdir -p "${OUTPUT_DIR}"

  cat > "${OUTPUT_DIR}/enrollment.env" <<EOFOUT
# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ')
STACK_VERSION=${STACK_VERSION}
FLEET_URL=${FLEET_PUBLIC_URL}
ELASTICSEARCH_URL=${ELASTIC_PUBLIC_URL}
KIBANA_URL=http://$(printf '%s' "${ELASTIC_PUBLIC_URL}" | sed -E 's#^http://([^:/]+)(:[0-9]+)?$#\1#'):${KIBANA_PORT}
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
ENDPOINT_POLICY_ID=${endpoint_policy_id}
ENDPOINT_PACKAGE_POLICY_ID=${endpoint_package_policy_id}
ENDPOINT_PACKAGE_VERSION=${endpoint_pkg_version}
  ENROLLMENT_TOKEN=${endpoint_enrollment_token}
EOFOUT

  write_agent_enrollment_examples "${endpoint_enrollment_token}"
  write_windows_enrollment_script

  cat > "${OUTPUT_DIR}/Enroll-ElasticAgent-LabDefaults.ps1" <<EOFOUT
[CmdletBinding()]
param(
    [switch]\$ForceReinstall,
    [switch]\$UninstallOnly
)

\$ScriptDir = Split-Path -Parent \$MyInvocation.MyCommand.Path
\$Installer = Join-Path \$ScriptDir 'Enroll-ElasticAgent.ps1'
if (-not (Test-Path \$Installer)) {
    throw \"Expected Enroll-ElasticAgent.ps1 in \$ScriptDir\"
}

& \$Installer -FleetUrl '${FLEET_PUBLIC_URL}' -EnrollmentToken '${endpoint_enrollment_token}' -AgentVersion '${STACK_VERSION}' -Insecure:\$true -InstallSysmon:\$true -ForceReinstall:\$ForceReinstall -UninstallOnly:\$UninstallOnly
EOFOUT

  if [[ -n "${fleet_server_policy_id}" && -n "${fleet_service_token}" ]]; then
    write_fleet_server_install_example "${fleet_server_policy_id}" "${fleet_service_token}"
  fi
}

resolve_public_urls() {
  local detected_ip=""
  detected_ip="$(detect_primary_ip || true)"

  FLEET_PUBLIC_URL="${FLEET_PUBLIC_URL:-${FLEET_URL:-}}"
  ELASTIC_PUBLIC_URL="${ELASTIC_PUBLIC_URL:-${ELASTICSEARCH_URL:-}}"

  if [[ -z "${FLEET_PUBLIC_URL}" && -n "${detected_ip}" ]]; then
    FLEET_PUBLIC_URL="http://${detected_ip}:${FLEET_SERVER_PORT}"
    log "Auto-detected FLEET_PUBLIC_URL=${FLEET_PUBLIC_URL} (override if wrong NIC)"
  fi
  if [[ -z "${ELASTIC_PUBLIC_URL}" && -n "${detected_ip}" ]]; then
    ELASTIC_PUBLIC_URL="http://${detected_ip}:${ES_PORT}"
    log "Auto-detected ELASTIC_PUBLIC_URL=${ELASTIC_PUBLIC_URL} (override if wrong NIC)"
  fi

  [[ -n "${FLEET_PUBLIC_URL}" ]] || die "Set FLEET_PUBLIC_URL=http://<lab-ip>:${FLEET_SERVER_PORT}"
  [[ -n "${ELASTIC_PUBLIC_URL}" ]] || die "Set ELASTIC_PUBLIC_URL=http://<lab-ip>:${ES_PORT}"
}

confirm_destructive_action() {
  local action="$1"
  if [[ "${AUTO_CONFIRM}" == "true" ]]; then
    return 0
  fi
  cat <<EOFMSG
This will ${action}.

Type YES to continue:
EOFMSG
  local ans
  read -r ans
  [[ "${ans}" == "YES" ]] || die "Aborted"
}

bootstrap_lab() {
  install_host_prereqs
  need_cmd docker
  need_cmd curl
  need_cmd jq
  need_cmd openssl
  check_host_prereqs
  ensure_docker_compose_available

  resolve_public_urls
  load_or_create_secrets

  write_compose_files
  compose_up_es
  wait_for_elasticsearch
  set_kibana_system_password
  compose_up_kibana
  wait_for_kibana
  ensure_advanced_license
  fleet_api_setup

  local fleet_server_pkg_version
  fleet_server_pkg_version="$(ensure_package_installed "fleet_server")"
  ensure_package_installed "system" >/dev/null
  local endpoint_pkg_version
  endpoint_pkg_version="$(ensure_package_installed "endpoint")"

  local fleet_server_policy_id
  fleet_server_policy_id="$(ensure_fleet_server_policy)"
  ensure_fleet_server_package_policy "${fleet_server_policy_id}" "${fleet_server_pkg_version}" >/dev/null

  local fleet_service_token
  fleet_service_token="$(create_fleet_service_token)"
  ensure_fleet_server_runtime "${fleet_server_policy_id}" "${fleet_service_token}"
  ensure_threat_intel_integration "${fleet_server_policy_id}"

  local endpoint_policy_id
  endpoint_policy_id="$(ensure_endpoint_agent_policy)"

  local endpoint_package_policy_id
  endpoint_package_policy_id="$(ensure_endpoint_defend_integration "${endpoint_policy_id}" "${endpoint_pkg_version}")"
  apply_endpoint_hardening "${endpoint_package_policy_id}" "${LAST_ENDPOINT_PACKAGE_POLICY_ITEM}"
  ensure_osquery_manager_integration "${endpoint_policy_id}"
  ensure_windows_integration "${endpoint_policy_id}"
  install_prebuilt_detection_rules

  local enrollment_token
  enrollment_token="$(create_enrollment_api_key "${endpoint_policy_id}")"

  write_outputs \
    "${endpoint_policy_id}" \
    "${endpoint_package_policy_id}" \
    "${enrollment_token}" \
    "${endpoint_pkg_version}" \
    "${fleet_server_policy_id}" \
    "${fleet_service_token}"

  cat <<EOFMSG

Fresh install complete.

Elastic URLs:
  Elasticsearch: ${ELASTIC_PUBLIC_URL}
  Kibana:        http://$(printf '%s' "${ELASTIC_PUBLIC_URL}" | sed -E 's#^http://([^:/]+)(:[0-9]+)?$#\1#'):${KIBANA_PORT}
  Fleet Server:  ${FLEET_PUBLIC_URL}

Credentials:
  Username: elastic
  Password: ${ELASTIC_PASSWORD}

Enrollment token (endpoint policy):
  ${enrollment_token}

Generated files:
  ${OUTPUT_DIR}/enrollment.env
  ${OUTPUT_DIR}/Enroll-ElasticAgent.ps1
  ${OUTPUT_DIR}/Enroll-ElasticAgent-LabDefaults.ps1
  ${OUTPUT_DIR}/windows-enroll-example.txt
  ${OUTPUT_DIR}/linux-enroll-example.sh
  ${OUTPUT_DIR}/linux-arm64-enroll-example.sh
  ${OUTPUT_DIR}/macos-enroll-example.sh
  ${OUTPUT_DIR}/macos-arm64-enroll-example.sh
  ${OUTPUT_DIR}/fleet-server-install-example.sh
  ${COMPOSE_FILE}
  ${SECRETS_FILE}

Notes:
  - Elastic Defend uses preset=EDRComplete.
  - Malware/ransomware/memory/behavior protections are forced to prevent mode where available.
  - LSASS-adjacent credential hardening is disabled by default via DISABLE_WINDOWS_LSASS_PROTECTION=${DISABLE_WINDOWS_LSASS_PROTECTION}.
  - FLEET_SERVER_MODE=${FLEET_SERVER_MODE}. If you are reusing a manual Fleet Server, set FLEET_SERVER_MODE=external.
  - If Fleet Server is external and not already running, use ${OUTPUT_DIR}/fleet-server-install-example.sh on the Fleet Server host.
EOFMSG
}

reset_lab() {
  if [[ -f "${COMPOSE_FILE}" && -f "${ENV_FILE}" ]]; then
    log "Stopping compose stack and removing volumes"
    compose_cmd down -v || true
  fi

  log "Removing Fleet Server container and state volume"
  docker rm -f "${FLEET_SERVER_CONTAINER}" >/dev/null 2>&1 || true
  docker volume rm "${FLEET_SERVER_STATE_VOLUME}" >/dev/null 2>&1 || true

  log "Removing runtime directory: ${LAB_ROOT}"
  rm -rf "${LAB_ROOT}"
  log "Reset complete"
}

enforce_defend_policy() {
  need_cmd curl
  need_cmd jq
  load_existing_secrets_if_present
  ensure_advanced_license

  local endpoint_policy_id
  endpoint_policy_id="$(agent_policy_id_by_name "${ENDPOINT_POLICY_NAME}")"
  [[ -n "${endpoint_policy_id}" ]] || die "Endpoint policy '${ENDPOINT_POLICY_NAME}' not found"

  local endpoint_package_policy_id
  endpoint_package_policy_id="$(endpoint_package_policy_id_for_agent_policy "${endpoint_policy_id}")"
  [[ -n "${endpoint_package_policy_id}" ]] || die "Endpoint package policy not found for '${ENDPOINT_POLICY_NAME}'"

  apply_endpoint_hardening "${endpoint_package_policy_id}" "${LAST_ENDPOINT_PACKAGE_POLICY_ITEM}"
  ensure_osquery_manager_integration "${endpoint_policy_id}"
  ensure_windows_integration "${endpoint_policy_id}"
  install_prebuilt_detection_rules
  log "Elastic Defend hardening enforcement completed"
}

rebuild_lab() {
  confirm_destructive_action "destroy the current Elastic lab state and rebuild it"
  ensure_vm_max_map_count
  reset_lab
  bootstrap_lab
}

refresh_lab() {
  rebuild_lab
}

recover_fleet_server() {
  install_host_prereqs
  need_cmd docker
  need_cmd curl
  need_cmd jq
  need_cmd openssl
  load_existing_secrets_if_present
  load_enrollment_env_if_present
  resolve_public_urls
  fleet_api_setup

  local fleet_server_pkg_version
  fleet_server_pkg_version="$(ensure_package_installed "fleet_server")"

  local fleet_server_policy_id
  fleet_server_policy_id="$(ensure_fleet_server_policy)"
  ensure_fleet_server_package_policy "${fleet_server_policy_id}" "${fleet_server_pkg_version}" >/dev/null

  local fleet_service_token
  fleet_service_token="$(create_fleet_service_token)"
  mkdir -p "${OUTPUT_DIR}"
  write_fleet_server_install_example "${fleet_server_policy_id}" "${fleet_service_token}"
  ensure_fleet_server_runtime "${fleet_server_policy_id}" "${fleet_service_token}"
}

health_check() {
  need_cmd curl
  need_cmd jq
  load_existing_secrets_if_present
  load_enrollment_env_if_present

  local fleet_status_base="http://127.0.0.1:${FLEET_SERVER_PORT}"
  if ! fleet_server_status_json "${fleet_status_base}" >/dev/null 2>&1 && [[ -n "${FLEET_PUBLIC_URL:-}" ]]; then
    fleet_status_base="${FLEET_PUBLIC_URL}"
  fi

  echo "== Elasticsearch auth =="
  curl -fsS -u "elastic:${ELASTIC_PASSWORD}" "${ES_URL_LOCAL}/_security/_authenticate?pretty" | jq '{username,roles}'
  echo

  echo "== License =="
  curl -fsS -u "elastic:${ELASTIC_PASSWORD}" "${ES_URL_LOCAL}/_license?pretty" | jq '.license | {type,status}'
  echo

  echo "== Kibana status =="
  curl -fsS -u "elastic:${ELASTIC_PASSWORD}" "${KIBANA_URL}/api/status" | jq '.status.overall.level'
  echo

  echo "== Fleet setup =="
  kibana_get '/api/fleet/agent_policies?perPage=1000' | jq '.items | length'
  echo

  echo "== Fleet Server status =="
  fleet_server_status_json "${fleet_status_base}" | jq '{name,status}' || echo "Fleet Server unreachable at ${fleet_status_base}"
  echo

  echo "== Agent policies =="
  kibana_get '/api/fleet/agent_policies?perPage=1000' | jq -r '.items[] | [.id,.name,.has_fleet_server,.is_default_fleet_server] | @tsv'
  echo

  echo "== Endpoint package policies =="
  kibana_get '/api/fleet/package_policies?perPage=1000' | jq -r '.items[] | select(.package.name=="endpoint") | [.id,.name,.policy_id] | @tsv'
  echo

  echo "== Key integration package policies =="
  kibana_get '/api/fleet/package_policies?perPage=1000' | jq -r '
    .items[]
    | select(
        .package.name=="endpoint" or
        .package.name=="windows" or
        .package.name=="osquery_manager" or
        .package.name=="fleet_server" or
        .package.name=="ti_abusech" or
        .package.name=="threat_intel" or
        .package.name=="ti_otx" or
        .package.name=="ti_opencti" or
        .package.name=="ti_anomali" or
        .package.name=="ti_misp"
      )
    | [.package.name,.id,.name,.policy_id,.enabled]
    | @tsv
  '
  echo

  echo "== Endpoint hardening summary =="
  local endpoint_policy_id endpoint_package_policy_id
  endpoint_policy_id="$(agent_policy_id_by_name "${ENDPOINT_POLICY_NAME}" || true)"
  if [[ -n "${endpoint_policy_id}" ]]; then
    endpoint_package_policy_id="$(endpoint_package_policy_id_for_agent_policy "${endpoint_policy_id}" || true)"
    if [[ -n "${endpoint_package_policy_id}" ]]; then
      summarize_endpoint_hardening "${endpoint_package_policy_id}" | jq '.'
    else
      echo "Endpoint package policy missing for ${ENDPOINT_POLICY_NAME}"
    fi
  else
    echo "Endpoint policy '${ENDPOINT_POLICY_NAME}' not found"
  fi
  echo

  echo "== Detection rules status =="
  local rules_status rules_http rules_body
  rules_status="$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
    -H 'kbn-xsrf: health-check' \
    -H 'Accept: application/json' \
    -w '\n%{http_code}' \
    "${KIBANA_URL}/api/detection_engine/rules/_find?per_page=1&page=1" 2>/dev/null || true)"
  rules_http="$(tail -n1 <<<"${rules_status}")"
  rules_body="${rules_status%$'\n'*}"
  if [[ "${rules_http}" == "200" ]]; then
    jq -r '[.total // 0, .data[0].enabled // false] | @tsv' <<<"${rules_body}" \
      | awk -F'\t' '{printf "rules_total=%s sample_rule_enabled=%s\n",$1,$2}'
  else
    echo "rules_total=unknown sample_rule_enabled=unknown (detection API HTTP ${rules_http:-n/a})"
  fi
  echo

  echo "== Enrollment keys =="
  kibana_get '/api/fleet/enrollment_api_keys?perPage=1000' | jq -r '.list[] | [.name,.policy_id,.active] | @tsv'
  echo

  echo "== Enrolled agents =="
  kibana_get '/api/fleet/agents?perPage=1000' | jq -r '.items[] | [(.local_metadata.host.hostname // "<unknown>"),.policy_id,.last_checkin_status,.active] | @tsv'
}

detect_iface_ip() {
  local iface="$1"
  if command -v ip >/dev/null 2>&1; then
    ip -4 -o addr show dev "${iface}" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1
  fi
}

print_windows_download_commands() {
  local base_url="$1"
  cat <<EOFOUT
\$BaseUrl = '${base_url}'
\$Dst = Join-Path \$env:TEMP 'elastic-enroll'
New-Item -ItemType Directory -Path \$Dst -Force | Out-Null
Invoke-WebRequest "\$BaseUrl/Enroll-ElasticAgent.ps1" -OutFile (Join-Path \$Dst 'Enroll-ElasticAgent.ps1')
Invoke-WebRequest "\$BaseUrl/Enroll-ElasticAgent-LabDefaults.ps1" -OutFile (Join-Path \$Dst 'Enroll-ElasticAgent-LabDefaults.ps1')
Set-ExecutionPolicy -Scope Process Bypass -Force
& (Join-Path \$Dst 'Enroll-ElasticAgent-LabDefaults.ps1') -ForceReinstall
EOFOUT
}

choose_enrollment_target() {
  cat >&2 <<'EOFMSG'
Choose enrollment target:
  1) windows-x86_64
  2) linux-x86_64
  3) linux-arm64
  4) macos-x86_64
  5) macos-arm64
EOFMSG
  local selection
  read -r selection
  case "${selection}" in
    1) printf 'windows x86_64\n' ;;
    2) printf 'linux x86_64\n' ;;
    3) printf 'linux arm64\n' ;;
    4) printf 'macos x86_64\n' ;;
    5) printf 'macos arm64\n' ;;
    *) die "Invalid selection" ;;
  esac
}

resolve_enrollment_base_url() {
  load_enrollment_env_if_present
  local bind_ip="${ENROLLMENT_HTTP_BIND_IP}"
  if [[ -z "${bind_ip}" ]]; then
    bind_ip="$(detect_iface_ip "${ENROLLMENT_HTTP_IFACE}" || true)"
  fi
  if [[ -z "${bind_ip}" ]]; then
    bind_ip="$(detect_primary_ip || true)"
  fi
  [[ -n "${bind_ip}" ]] || die "Could not detect an IP to bind. Set ENROLLMENT_HTTP_BIND_IP explicitly."

  printf 'http://%s:%s\n' "${bind_ip}" "${ENROLLMENT_HTTP_PORT}"
}

enrollment_example_filename() {
  local platform="$1"
  local arch="$2"
  case "${platform}:${arch}" in
    windows:x86_64) printf 'Enroll-ElasticAgent-LabDefaults.ps1\n' ;;
    linux:x86_64) printf 'linux-enroll-example.sh\n' ;;
    linux:arm64) printf 'linux-arm64-enroll-example.sh\n' ;;
    macos:x86_64) printf 'macos-enroll-example.sh\n' ;;
    macos:arm64) printf 'macos-arm64-enroll-example.sh\n' ;;
    *) die "Unsupported enrollment target ${platform}/${arch}" ;;
  esac
}

ensure_enrollment_artifacts_for_target() {
  local platform="$1"
  local arch="$2"
  [[ -d "${OUTPUT_DIR}" ]] || die "Missing output directory: ${OUTPUT_DIR}. Run fresh-install first."
  case "${platform}:${arch}" in
    windows:x86_64)
      [[ -f "${OUTPUT_DIR}/Enroll-ElasticAgent.ps1" ]] || die "Missing ${OUTPUT_DIR}/Enroll-ElasticAgent.ps1. Run fresh-install first."
      [[ -f "${OUTPUT_DIR}/Enroll-ElasticAgent-LabDefaults.ps1" ]] || die "Missing ${OUTPUT_DIR}/Enroll-ElasticAgent-LabDefaults.ps1. Run fresh-install first."
      ;;
    *)
      local example_file
      example_file="$(enrollment_example_filename "${platform}" "${arch}")"
      [[ -f "${OUTPUT_DIR}/${example_file}" ]] || die "Missing ${OUTPUT_DIR}/${example_file}. Run fresh-install first."
      ;;
  esac
}

ensure_enrollment_token_available() {
  load_enrollment_env_if_present
  if [[ -n "${ENROLLMENT_TOKEN:-}" ]]; then
    return 0
  fi

  load_existing_secrets_if_present
  resolve_public_urls
  if curl -fsS -u "elastic:${ELASTIC_PASSWORD}" "${KIBANA_URL}/api/status" >/dev/null 2>&1; then
    local endpoint_policy_id
    endpoint_policy_id="$(agent_policy_id_by_name "${ENDPOINT_POLICY_NAME}" || true)"
    [[ -n "${endpoint_policy_id}" ]] || die "Missing enrollment token and endpoint policy '${ENDPOINT_POLICY_NAME}' was not found."
    ENROLLMENT_TOKEN="$(create_enrollment_api_key "${endpoint_policy_id}")"
    refresh_enrollment_outputs "${endpoint_policy_id}" "${ENROLLMENT_TOKEN}"
    log "Created a fresh enrollment token for ${ENDPOINT_POLICY_NAME}"
    return 0
  fi

  die "Missing enrollment token. Run fresh-install first."
}

refresh_enrollment_outputs() {
  local endpoint_policy_id="$1"
  local enrollment_token="$2"
  local endpoint_package_policy_id endpoint_pkg_version

  endpoint_package_policy_id="$(endpoint_package_policy_id_for_agent_policy "${endpoint_policy_id}" || true)"
  [[ -n "${endpoint_package_policy_id}" ]] || die "Endpoint package policy not found for '${ENDPOINT_POLICY_NAME}'"

  endpoint_pkg_version="$(kibana_get '/api/fleet/package_policies?perPage=1000' \
    | jq -r --arg id "${endpoint_package_policy_id}" 'first(.items[]? | select(.id==$id) | .package.version) // empty')"
  [[ -n "${endpoint_pkg_version}" ]] || die "Could not resolve endpoint package version for policy ${endpoint_package_policy_id}"

  write_outputs \
    "${endpoint_policy_id}" \
    "${endpoint_package_policy_id}" \
    "${enrollment_token}" \
    "${endpoint_pkg_version}"
}

print_hosted_enrollment_command() {
  local platform="$1"
  local arch="$2"
  local base_url="$3"
  case "${platform}:${arch}" in
    windows:x86_64)
      print_windows_download_commands "${base_url}"
      ;;
    linux:x86_64)
      printf "curl -fsSL '%s/linux-enroll-example.sh' | bash\n" "${base_url}"
      ;;
    linux:arm64)
      printf "curl -fsSL '%s/linux-arm64-enroll-example.sh' | bash\n" "${base_url}"
      ;;
    macos:x86_64)
      printf "curl -fsSL '%s/macos-enroll-example.sh' | bash\n" "${base_url}"
      ;;
    macos:arm64)
      printf "curl -fsSL '%s/macos-arm64-enroll-example.sh' | bash\n" "${base_url}"
      ;;
    *)
      die "Unsupported enrollment target ${platform}/${arch}"
      ;;
  esac
}

serve_enrollment_files() {
  need_cmd python3
  ensure_enrollment_artifacts_for_target windows x86_64
  local base_url bind_ip
  base_url="$(resolve_enrollment_base_url)"
  bind_ip="${base_url#http://}"
  bind_ip="${bind_ip%:${ENROLLMENT_HTTP_PORT}}"
  cat <<EOFMSG
Serving enrollment artifacts from:
  ${OUTPUT_DIR}

HTTP endpoint:
  ${base_url}

Windows PowerShell:
$(print_windows_download_commands "${base_url}")
EOFMSG

  log "Starting HTTP server on ${base_url} (Ctrl+C to stop)"
  exec python3 -m http.server "${ENROLLMENT_HTTP_PORT}" --bind "${bind_ip}" --directory "${OUTPUT_DIR}"
}

enroll_host() {
  need_cmd python3
  ensure_enrollment_token_available
  local platform="${1:-}"
  local arch="${2:-}"
  if [[ -z "${platform}" ]]; then
    local target
    target="$(choose_enrollment_target)"
    platform="${target%% *}"
    arch="${target##* }"
  fi

  arch="${arch:-x86_64}"
  ensure_enrollment_artifacts_for_target "${platform}" "${arch}"

  local base_url bind_ip server_pid example_file
  base_url="$(resolve_enrollment_base_url)"
  bind_ip="${base_url#http://}"
  bind_ip="${bind_ip%:${ENROLLMENT_HTTP_PORT}}"
  example_file="$(enrollment_example_filename "${platform}" "${arch}")"

  python3 -m http.server "${ENROLLMENT_HTTP_PORT}" --bind "${bind_ip}" --directory "${OUTPUT_DIR}" >/dev/null 2>&1 &
  server_pid=$!
  sleep 1
  kill -0 "${server_pid}" >/dev/null 2>&1 || die "Failed to start HTTP server on ${base_url}"

  trap 'kill "${server_pid}" >/dev/null 2>&1 || true; wait "${server_pid}" 2>/dev/null || true' EXIT
  cat <<EOFMSG
Target:
  ${platform}-${arch}

Serving enrollment artifacts from:
  ${OUTPUT_DIR}

HTTP endpoint:
  ${base_url}

Primary hosted command for the target:
$(print_hosted_enrollment_command "${platform}" "${arch}" "${base_url}")

Served file:
  ${base_url}/${example_file}

Direct enrollment command:
$(print_agent_enrollment_command "${platform}" "${arch}" "${ENROLLMENT_TOKEN}")

Press ENTER to stop serving enrollment files.
EOFMSG

  local _
  read -r _
  kill "${server_pid}" >/dev/null 2>&1 || true
  wait "${server_pid}" 2>/dev/null || true
  trap - EXIT
}

generate_enrollment() {
  enroll_host "$@"
}

print_usage() {
  cat <<'EOFMSG'
Usage:
  ./ElasticLabDeploy.sh [command]

Commands:
  menu                 Interactive menu
  fresh-install        Deploy Elasticsearch, Kibana, Fleet, Fleet Server, and hardened Elastic Defend
  bootstrap            Alias for fresh-install
  install-prereqs      Install host prerequisites
  enroll-host          Pick a target OS/arch, serve enrollment files, and print the target command
  health-check         Print stack, Fleet, policy, and enrollment status
  rebuild-lab          Destroy runtime state and redeploy the lab (retries trial activation)
  reset-lab            Destroy runtime state and containers only
  help                 Show this message
EOFMSG
}

interactive_menu() {
  while true; do
    cat <<'EOFMSG'
ElasticLabDeploy Menu
  1) Fresh install / repair lab
  2) Enroll a host
  3) Health check
  4) Rebuild lab from scratch (retry trial)
  5) Destroy lab state only
  6) Exit
EOFMSG
    local choice
    read -r -p "Select option: " choice
    case "${choice}" in
      1) bootstrap_lab ;;
      2) enroll_host ;;
      3) health_check ;;
      4) rebuild_lab ;;
      5)
        confirm_destructive_action "destroy the current Elastic lab state"
        reset_lab
        ;;
      6) return 0 ;;
      *) echo "Invalid selection" ;;
    esac
    echo
  done
}

dispatch_command() {
  local cmd="${1:-menu}"
  shift || true
  case "${cmd}" in
    menu) interactive_menu ;;
    bootstrap|fresh-install) bootstrap_lab ;;
    install-prereqs) install_host_prereqs ;;
    enroll-host|generate-enrollment|serve-enrollment) enroll_host "$@" ;;
    health-check) health_check ;;
    enforce-defend|enforce-edr-prevent) enforce_defend_policy ;;
    recover-fleet-server|recover) recover_fleet_server ;;
    reset|reset-lab)
      confirm_destructive_action "destroy the current Elastic lab state"
      reset_lab
      ;;
    rebuild-lab|refresh) rebuild_lab ;;
    help|-h|--help) print_usage ;;
    *) die "Unknown command: ${cmd}" ;;
  esac
}

main() {
  local cmd="${1:-menu}"
  maybe_self_elevate "${cmd}" "$@"
  dispatch_command "$@"
}

main "$@"
