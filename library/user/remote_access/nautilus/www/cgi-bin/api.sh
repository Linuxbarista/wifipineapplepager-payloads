#!/bin/sh

PAYLOAD_ROOT="/root/payloads/user"
PID_FILE="/tmp/nautilus_payload.pid"
OUTPUT_FILE="/tmp/nautilus_output.log"
CACHE_FILE="/tmp/nautilus_cache.json"
AUTH_CHALLENGE_FILE="/tmp/nautilus_auth_challenge"
AUTH_SESSION_FILE="/tmp/nautilus_auth_session"
SESSION_TIMEOUT=3600

# --- Authentication ---
generate_challenge() {
    local challenge=$(head -c 32 /dev/urandom 2>/dev/null | md5sum | cut -d' ' -f1)
    local timestamp=$(date +%s)
    echo "${challenge}:${timestamp}" > "$AUTH_CHALLENGE_FILE"
    echo "Content-Type: application/json"
    echo ""
    echo "{\"challenge\":\"$challenge\"}"
}

verify_auth() {
    local nonce="$1"
    local encrypted_b64="$2"

    # Check challenge exists and is recent
    if [ ! -f "$AUTH_CHALLENGE_FILE" ]; then
        echo "Content-Type: application/json"
        echo ""
        echo '{"error":"No challenge issued"}'
        exit 1
    fi

    local stored=$(cat "$AUTH_CHALLENGE_FILE")
    local stored_challenge="${stored%%:*}"
    local stored_time="${stored##*:}"
    local now=$(date +%s)

    # Challenge expires after 60 seconds
    if [ $((now - stored_time)) -gt 60 ]; then
        rm -f "$AUTH_CHALLENGE_FILE"
        echo "Content-Type: application/json"
        echo ""
        echo '{"error":"Challenge expired"}'
        exit 1
    fi

    if [ "$nonce" != "$stored_challenge" ]; then
        echo "Content-Type: application/json"
        echo ""
        echo '{"error":"Invalid challenge"}'
        exit 1
    fi

    # Consume challenge
    rm -f "$AUTH_CHALLENGE_FILE"

    # Decode base64 and XOR with key to get password
    # Client sends: base64(XOR(password_bytes, sha256(nonce+password)[:len(password)]))
    # We need to try decoding - since we don't know password, we use a different approach:
    # Client sends: base64(password) XOR'd with first N bytes of sha256(nonce)
    # This way server can decode without knowing password first

    local key_hex=$(printf '%s' "$nonce" | openssl dgst -sha256 -hex 2>/dev/null | cut -d' ' -f2)
    local encrypted_hex=$(echo "$encrypted_b64" | base64 -d 2>/dev/null | hexdump -ve '1/1 "%02x"' 2>/dev/null)

    if [ -z "$encrypted_hex" ]; then
        echo "Content-Type: application/json"
        echo ""
        echo '{"error":"Decode failed"}'
        exit 1
    fi

    # XOR decrypt
    local password=""
    local i=0
    local len=${#encrypted_hex}
    while [ $i -lt $len ]; do
        local enc_byte=$(echo "$encrypted_hex" | cut -c$((i+1))-$((i+2)))
        local key_byte=$(echo "$key_hex" | cut -c$((i+1))-$((i+2)))
        if [ -z "$key_byte" ]; then
            key_byte="00"
        fi
        local dec_byte=$(printf '%02x' $((0x$enc_byte ^ 0x$key_byte)))
        password="${password}$(printf "\\x${dec_byte}")"
        i=$((i + 2))
    done

    # Verify against shadow
    local shadow_entry=$(grep '^root:' /etc/shadow 2>/dev/null)
    local shadow_hash=$(echo "$shadow_entry" | cut -d: -f2)
    local salt=$(echo "$shadow_hash" | cut -d'$' -f1-3)

    # Generate hash with same salt
    local test_hash=$(openssl passwd -1 -salt "$(echo "$salt" | cut -d'$' -f3)" "$password" 2>/dev/null)

    if [ "$test_hash" = "$shadow_hash" ]; then
        # Generate session token
        local session=$(head -c 32 /dev/urandom 2>/dev/null | md5sum | cut -d' ' -f1)
        local session_time=$(date +%s)
        echo "${session}:${session_time}" > "$AUTH_SESSION_FILE"
        echo "Content-Type: application/json"
        echo "Set-Cookie: nautilus_session=$session; Path=/; HttpOnly; SameSite=Strict"
        echo ""
        echo '{"success":true}'
    else
        echo "Content-Type: application/json"
        echo ""
        echo '{"error":"Invalid password"}'
    fi
}

check_session() {
    # Extract session cookie
    local session=""
    local cookies="$HTTP_COOKIE"
    local IFS=';'
    for cookie in $cookies; do
        cookie=$(echo "$cookie" | sed 's/^ *//')
        case "$cookie" in
            nautilus_session=*)
                session="${cookie#nautilus_session=}"
                ;;
        esac
    done
    unset IFS

    if [ -z "$session" ]; then
        return 1
    fi

    if [ ! -f "$AUTH_SESSION_FILE" ]; then
        return 1
    fi

    local stored=$(cat "$AUTH_SESSION_FILE")
    local stored_session="${stored%%:*}"
    local stored_time="${stored##*:}"
    local now=$(date +%s)

    # Session expires after SESSION_TIMEOUT
    if [ $((now - stored_time)) -gt $SESSION_TIMEOUT ]; then
        rm -f "$AUTH_SESSION_FILE"
        return 1
    fi

    if [ "$session" = "$stored_session" ]; then
        return 0
    fi

    return 1
}

require_auth() {
    if ! check_session; then
        echo "Content-Type: application/json"
        echo ""
        echo '{"error":"Authentication required","code":"AUTH_REQUIRED"}'
        exit 1
    fi
}

csrf_check() {
    local action="$1"

    case "$action" in
        list) return 0 ;;
    esac

    local origin="$HTTP_ORIGIN"
    local referer="$HTTP_REFERER"
    local host="$HTTP_HOST"

    if [ -n "$origin" ]; then
        local origin_host=$(echo "$origin" | sed 's|^https\?://||' | sed 's|/.*||')
        if [ "$origin_host" != "$host" ]; then
            echo "Content-Type: application/json"
            echo ""
            echo '{"error":"CSRF protection: Origin mismatch"}'
            exit 1
        fi
        return 0
    fi

    if [ -n "$referer" ]; then
        local referer_host=$(echo "$referer" | sed 's|^https\?://||' | sed 's|/.*||')
        if [ "$referer_host" != "$host" ]; then
            echo "Content-Type: application/json"
            echo ""
            echo '{"error":"CSRF protection: Referer mismatch"}'
            exit 1
        fi
        return 0
    fi

    # No Origin AND no Referer
    echo "Content-Type: application/json"
    echo ""
    echo '{"error":"CSRF protection: Missing Origin/Referer"}'
    exit 1
}

urldecode() {
    printf '%b' "$(echo "$1" | sed 's/+/ /g; s/%\([0-9A-Fa-f][0-9A-Fa-f]\)/\\x\1/g')"
}

TOKEN_FILE="/tmp/nautilus_csrf_token"

generate_token() {
    local token=$(head -c 16 /dev/urandom 2>/dev/null | md5sum | cut -d' ' -f1)
    if [ -z "$token" ]; then
        token=$(date +%s%N | md5sum | cut -d' ' -f1)
    fi
    echo "$token" > "$TOKEN_FILE"
    echo "Content-Type: application/json"
    echo ""
    echo "{\"token\":\"$token\"}"
}

validate_token() {
    local provided="$1"
    if [ ! -f "$TOKEN_FILE" ]; then
        return 1
    fi
    local stored=$(cat "$TOKEN_FILE")
    rm -f "$TOKEN_FILE"
    if [ "$provided" = "$stored" ] && [ -n "$stored" ]; then
        return 0
    fi
    return 1
}

list_payloads() {
    echo "Content-Type: application/json"
    echo ""
    if [ -f "$CACHE_FILE" ]; then
        cat "$CACHE_FILE"
    else
        echo '{"error":"Cache not ready. Refresh page."}'
    fi
}

run_payload() {
    rpath="$1"
    token="$2"

    if ! validate_token "$token"; then
        echo "Content-Type: text/plain"
        echo ""
        echo "CSRF protection: Invalid or missing token. Refresh and try again."
        exit 1
    fi

    # Path Traversal Protection
    case "$rpath" in
        *..*)
            echo "Content-Type: text/plain"
            echo ""
            echo "Security: Path traversal not allowed"
            exit 1
            ;;
    esac

    case "$rpath" in
        /root/payloads/user/*) ;;
        *) echo "Content-Type: text/plain"; echo ""; echo "Invalid path"; exit 1 ;;
    esac

    case "$rpath" in
        */payload.sh) ;;
        *) echo "Content-Type: text/plain"; echo ""; echo "Invalid payload file"; exit 1 ;;
    esac

    [ ! -f "$rpath" ] && { echo "Content-Type: text/plain"; echo ""; echo "Not found"; exit 1; }
    [ -f "$PID_FILE" ] && { kill $(cat "$PID_FILE") 2>/dev/null; rm -f "$PID_FILE"; }

    echo "Content-Type: text/event-stream"
    echo "Cache-Control: no-cache"
    echo ""

    # Create wrapper script that intercepts pager commands
    WRAPPER="/tmp/nautilus_wrapper_$$.sh"
    cat > "$WRAPPER" << 'WRAPPER_EOF'
#!/bin/bash

_nautilus_emit() {
    local color="$1"
    shift
    local text="$*"
    # Output for web console
    if [ -n "$color" ]; then
        echo "[${color}] ${text}"
    else
        echo "$text"
    fi
}

LOG() {
    local color=""
    if [ "$#" -gt 1 ]; then
        color="$1"
        shift
    fi
    _nautilus_emit "$color" "$@"
    /usr/bin/LOG ${color:+"$color"} "$@" 2>/dev/null || true
}

ALERT() {
    # Display in Nautilus only - don't pop up on pager
    echo "[PROMPT:alert] $*" >&2
    sleep 0.1
    _wait_response ""
}

ERROR_DIALOG() {
    # Display in Nautilus only - don't pop up on pager
    echo "[PROMPT:error] $*" >&2
    sleep 0.1
    _wait_response ""
}

LED() {
    _nautilus_emit "blue" "LED: $*"
    /usr/bin/LED "$@" 2>/dev/null || true
}

_wait_response() {
    local resp_file="/tmp/nautilus_response"
    local default="$1"
    rm -f "$resp_file"
    local timeout=300
    while [ ! -f "$resp_file" ] && [ $timeout -gt 0 ]; do
        sleep 0.5
        timeout=$((timeout - 1))
    done
    if [ -f "$resp_file" ]; then
        cat "$resp_file"
        rm -f "$resp_file"
    else
        echo -n "$default"
    fi
}

CONFIRMATION_DIALOG() {
    local msg="$*"
    echo "[PROMPT:confirm] $msg" >&2
    sleep 0.1
    local resp=$(_wait_response "0")
    if [ "$resp" = "1" ]; then
        echo -n "1"
    else
        echo -n "0"
    fi
}

PROMPT() {
    local msg="$*"
    echo "[PROMPT:text] $msg" >&2
    _wait_response ""
}

TEXT_PICKER() {
    local title="$1"
    local default="$2"
    echo "[PROMPT:text:$default] $title" >&2
    _wait_response "$default"
}

NUMBER_PICKER() {
    local title="$1"
    local default="$2"
    echo "[PROMPT:number:$default] $title" >&2
    _wait_response "$default"
}

IP_PICKER() {
    local title="$1"
    local default="$2"
    echo "[PROMPT:ip:$default] $title" >&2
    _wait_response "$default"
}

MAC_PICKER() {
    local title="$1"
    local default="$2"
    echo "[PROMPT:mac:$default] $title" >&2
    _wait_response "$default"
}

SPINNER() {
    _nautilus_emit "cyan" "SPINNER: $*"
    /usr/bin/SPINNER "$@" 2>/dev/null || true
}

SPINNER_STOP() {
    _nautilus_emit "cyan" "SPINNER_STOP"
    /usr/bin/SPINNER_STOP 2>/dev/null || true
}

export -f LOG ALERT ERROR_DIALOG LED CONFIRMATION_DIALOG PROMPT TEXT_PICKER NUMBER_PICKER IP_PICKER MAC_PICKER SPINNER SPINNER_STOP _nautilus_emit _wait_response

cd "$(dirname "$1")"
source "$1"
WRAPPER_EOF
    chmod +x "$WRAPPER"

    : > "$OUTPUT_FILE"

    /bin/bash "$WRAPPER" "$rpath" >> "$OUTPUT_FILE" 2>&1 &
    WRAPPER_PID=$!
    echo $WRAPPER_PID > "$PID_FILE"

    sent_lines=0

    while kill -0 $WRAPPER_PID 2>/dev/null || [ $(wc -l < "$OUTPUT_FILE") -gt $sent_lines ]; do
        current_lines=$(wc -l < "$OUTPUT_FILE")
        if [ $current_lines -gt $sent_lines ]; then
            tail -n +$((sent_lines + 1)) "$OUTPUT_FILE" | head -n $((current_lines - sent_lines)) | while IFS= read -r line; do
            escaped=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g')
            case "$line" in
                "[PROMPT:"*)
                    inner="${line#\[PROMPT:}"
                    type="${inner%%\]*}"
                    msg="${inner#*\] }"
                    if echo "$type" | grep -q ':'; then
                        default="${type#*:}"
                        type="${type%%:*}"
                    else
                        default=""
                    fi
                    escaped_msg=$(printf '%s' "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g')
                    escaped_def=$(printf '%s' "$default" | sed 's/\\/\\\\/g; s/"/\\"/g')
                    printf 'event: prompt\ndata: {"type":"%s","message":"%s","default":"%s"}\n\n' "$type" "$escaped_msg" "$escaped_def"
                    continue ;;
            esac
            color=""
            case "$line" in
                "[red]"*) color="red" ;;
                "[green]"*) color="green" ;;
                "[yellow]"*) color="yellow" ;;
                "[cyan]"*) color="cyan" ;;
                "[blue]"*) color="blue" ;;
                "[magenta]"*) color="magenta" ;;
            esac
                if [ -n "$color" ]; then
                    printf 'data: {"text":"%s","color":"%s"}\n\n' "$escaped" "$color"
                else
                    printf 'data: {"text":"%s"}\n\n' "$escaped"
                fi
            done
            sent_lines=$current_lines
        fi
        sleep 0.2
    done
    printf 'event: done\ndata: {"status":"complete"}\n\n'
    rm -f "$WRAPPER" "$PID_FILE"
}

respond() {
    echo "Content-Type: application/json"
    echo ""
    local response="$1"

    # Response injection protection
    case "$response" in
        *[\$\`\;\|\&\>\<\(\)\{\}\[\]\!\#\*\?\\]*)
            echo '{"status":"error","message":"Invalid characters in response"}'
            exit 1
            ;;
    esac

    if [ ${#response} -gt 256 ]; then
        echo '{"status":"error","message":"Response too long"}'
        exit 1
    fi

    echo "$response" > "/tmp/nautilus_response"
    echo '{"status":"ok"}'
}

stop_payload() {
    echo "Content-Type: application/json"
    echo ""
    if [ -f "$PID_FILE" ]; then
        kill $(cat "$PID_FILE") 2>/dev/null
        rm -f "$PID_FILE"
        echo '{"status":"stopped"}'
    else
        echo '{"status":"not_running"}'
    fi
}

action=""
rpath=""
response=""
token=""
nonce=""
data=""
IFS='&'
for param in $QUERY_STRING; do
    key="${param%%=*}"
    val="${param#*=}"
    case "$key" in
        action) action="$val" ;;
        path) rpath=$(urldecode "$val") ;;
        response) response=$(urldecode "$val") ;;
        token) token=$(urldecode "$val") ;;
        nonce) nonce=$(urldecode "$val") ;;
        data) data=$(urldecode "$val") ;;
    esac
done
unset IFS

# Auth actions don't need CSRF or session check
case "$action" in
    challenge|auth|check_session) ;;
    run) ;;
    *)
        csrf_check "$action"
        require_auth
        ;;
esac

case "$action" in
    challenge) generate_challenge ;;
    auth) verify_auth "$nonce" "$data" ;;
    check_session)
        if check_session; then
            echo "Content-Type: application/json"
            echo ""
            echo '{"authenticated":true}'
        else
            echo "Content-Type: application/json"
            echo ""
            echo '{"authenticated":false}'
        fi
        ;;
    list) require_auth; list_payloads ;;
    token) require_auth; generate_token ;;
    run) require_auth; run_payload "$rpath" "$token" ;;
    stop) require_auth; stop_payload ;;
    respond) require_auth; respond "$response" ;;
    refresh) require_auth; /root/payloads/user/general/nautilus/build_cache.sh; echo "Content-Type: application/json"; echo ""; echo '{"status":"refreshed"}' ;;
    *) echo "Content-Type: application/json"; echo ""; echo '{"error":"Unknown action"}' ;;
esac

