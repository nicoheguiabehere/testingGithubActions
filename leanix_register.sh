#!/usr/bin/env bash
#
# LeanIX helper: sube el manifest de un microservicio (crea o actualiza su
# Fact Sheet) y registra su SBOM en ese Fact Sheet.
#
# Requisitos: bash 4+, curl, jq
#
# Variables de entorno:
#   LEANIX_API_TOKEN      (obligatoria) API token del Technical User
#   LEANIX_SUBDOMAIN      (obligatoria) subdominio de LeanIX (p. ej. "eu-10")
#   LEANIX_MANIFEST_FILE  (opcional)    por defecto: leanix.yaml
#   SBOM_FILE             (opcional)    por defecto: sbom.json

set -euo pipefail

# Timeout de las requests (segundos)
TIMEOUT=20

# Configuración de reintentos ante rate limiting
MAX_RETRIES=5
BASE_DELAY=1 # segundos

# El API token y el subdominio se definen como variables de entorno.
# Se recomienda no hardcodear información sensible en el código.
LEANIX_API_TOKEN="${LEANIX_API_TOKEN:-}"
LEANIX_SUBDOMAIN="${LEANIX_SUBDOMAIN:-}"
LEANIX_FQDN="https://${LEANIX_SUBDOMAIN}.leanix.net/services"

# URL OAuth2 para pedir el access token
LEANIX_OAUTH2_URL="${LEANIX_FQDN}/mtm/v1/oauth2/token"

# Manifest API
MANIFEST_API="${LEANIX_FQDN}/technology-discovery/v1/manifests"

# GitHub (no se usan actualmente; se mantienen por paridad con la versión Python)
GITHUB_SERVER_URL="${GITHUB_SERVER_URL:-}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}"
export GITHUB_SERVER_URL GITHUB_REPOSITORY

# Archivo manifest y archivo SBOM
LEANIX_MANIFEST_FILE="${LEANIX_MANIFEST_FILE:-leanix.yaml}"
SBOM_FILE="${SBOM_FILE:-sbom.json}"

# Directorio temporal para cuerpos y headers de las respuestas
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_info()    { echo "INFO: $*" >&2; }
log_warning() { echo "WARNING: $*" >&2; }
log_error()   { echo "ERROR: $*" >&2; }
die()         { log_error "$*"; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found"
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Verifica que el archivo exista y sea un archivo regular.
ensure_file() {
    [[ -f "$1" ]]
}

# Header de autorización para las llamadas a la API.
auth_header() {
    printf 'Authorization: Bearer %s' "${LEANIX_ACCESS_TOKEN:-}"
}

# Ejecuta una request HTTP. Imprime el body en stdout.
# Falla (return 1) ante error de curl o status HTTP >= 400.
# Uso: http_request <METHOD> <URL> [args de curl...]
http_request() {
    local method="$1" url="$2"
    shift 2
    local body="$TMP_DIR/body"
    local status

    status=$(curl -sS -X "$method" --max-time "$TIMEOUT" \
        -o "$body" -w '%{http_code}' "$@" "$url") || {
        log_error "Request failed: $method $url"
        return 1
    }

    if (( status >= 400 )); then
        log_error "HTTP $status for $method $url: $(cat "$body")"
        return 1
    fi
    cat "$body"
}

# Ejecuta una request HTTP con backoff exponencial ante respuestas 429.
# Respeta el header Retry-After si viene con un número de segundos.
# Uso: request_with_retry <METHOD> <URL> [args de curl...]
request_with_retry() {
    local method="$1" url="$2"
    shift 2
    local body="$TMP_DIR/retry_body"
    local headers="$TMP_DIR/retry_headers"
    local attempt status delay retry_after

    for (( attempt = 0; attempt < MAX_RETRIES; attempt++ )); do
        status=$(curl -sS -X "$method" --max-time "$TIMEOUT" \
            -D "$headers" -o "$body" -w '%{http_code}' "$@" "$url") || {
            log_error "Request failed: $method $url"
            return 1
        }

        if [[ "$status" == "429" ]]; then
            delay=$(( BASE_DELAY * (2 ** attempt) ))
            retry_after=$(awk -F': *' 'tolower($1) == "retry-after" { v = $2 } END { print v }' "$headers" | tr -d '\r[:space:]')
            if [[ "$retry_after" =~ ^[0-9]+$ ]]; then
                delay="$retry_after"
            fi
            log_warning "Rate limited. Retrying in ${delay}s (attempt $(( attempt + 1 ))/${MAX_RETRIES})"
            sleep "$delay"
            continue
        fi

        if (( status >= 400 )); then
            log_error "HTTP $status for $method $url: $(cat "$body")"
            return 1
        fi

        cat "$body"
        return 0
    done

    log_error "Max retries (${MAX_RETRIES}) exceeded due to rate limiting"
    return 1
}

# ---------------------------------------------------------------------------
# Lógica principal
# ---------------------------------------------------------------------------

# Obtiene un access token de LeanIX usando el API token del Technical User.
obtain_access_token() {
    [[ -n "$LEANIX_API_TOKEN" ]] || die "A valid token is required"

    local resp token
    resp=$(http_request POST "$LEANIX_OAUTH2_URL" \
        -u "apitoken:${LEANIX_API_TOKEN}" \
        --data-urlencode "grant_type=client_credentials") \
        || die "Could not obtain access token"

    token=$(jq -r '.access_token // empty' <<<"$resp") \
        || die "Invalid response from OAuth2 endpoint"
    [[ -n "$token" ]] || die "OAuth2 response did not contain an access_token"

    printf '%s' "$token"
}

# Registra el SBOM en el Fact Sheet indicado.
register_sboms() {
    local factsheet_id="$1"
    local sbom_name

    if ! ensure_file "$SBOM_FILE"; then
        log_warning "No sbom file found"
        return 0
    fi

    sbom_name="$(basename "$SBOM_FILE")"
    local sbom_endpoint="${LEANIX_FQDN}/technology-discovery/v1/factSheets/${factsheet_id}/sboms"
    log_info "Processing sbom file: ${sbom_name} for Fact Sheet: ${factsheet_id}"
    log_info "Sending SBOM ingestion request for Fact Sheet: ${factsheet_id}"

    request_with_retry POST "$sbom_endpoint" \
        -H "$(auth_header)" \
        -F "sbom=@${SBOM_FILE};type=application/json" >/dev/null \
        || die "Failed to submit SBOM for Fact Sheet: ${factsheet_id}"

    log_info "Successfully submitted SBOM request for Fact Sheet: ${factsheet_id}"
}

# Crea o actualiza el Fact Sheet del microservicio a partir del manifest
# y luego registra su SBOM.
create_or_update_micro_services() {
    local manifest_file="$1"
    local manifest_name resp factsheet_id

    manifest_name="$(basename "$manifest_file")"
    log_info "Processing manifest file: ${manifest_name}"

    # NOTA: application/yaml acá no es el content type de la request,
    # sino el tipo del archivo dentro del multipart.
    resp=$(http_request PUT "$MANIFEST_API" \
        -H "$(auth_header)" \
        -F "file=@${manifest_file};type=application/yaml") \
        || die "Failed to upload manifest file: ${manifest_name}"

    log_info "Successfully uploaded manifest file: ${manifest_name}"

    factsheet_id=$(jq -r '.data.factSheetId // empty' <<<"$resp") \
        || die "Invalid response from Manifest API"
    [[ -n "$factsheet_id" ]] || die "Service did not return a fact sheet ID"

    register_sboms "$factsheet_id"
}

main() {
    require_cmd curl
    require_cmd jq

    LEANIX_ACCESS_TOKEN="$(obtain_access_token)" || exit 1
    export LEANIX_ACCESS_TOKEN

    ensure_file "$LEANIX_MANIFEST_FILE" || die "File ${LEANIX_MANIFEST_FILE} not found"
    create_or_update_micro_services "$LEANIX_MANIFEST_FILE"
}

main "$@"
