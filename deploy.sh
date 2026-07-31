#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"

usage() {
    cat <<'EOF'
Usage: ./deploy.sh [--no-build]

Build and start ecs-controller with Docker Compose, then wait for /healthz.

Environment:
  ECS_SETUP_TOKEN  One-time token used during first-run initialization.
EOF
}

no_build=0
case "${1:-}" in
    "") ;;
    --no-build) no_build=1 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is not installed or not available in PATH." >&2
    exit 1
fi

compose_cmd=()
if docker compose version >/dev/null 2>&1; then
    compose_cmd=(docker compose)
elif command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then
    compose_cmd=(docker-compose)
else
    echo "Docker Compose is not available. Install the Docker Compose plugin." >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Docker is not running. Start Colima with: colima start" >&2
    exit 1
fi

generated_token=0
if [[ -z "${ECS_SETUP_TOKEN:-}" ]]; then
    if command -v openssl >/dev/null 2>&1; then
        ECS_SETUP_TOKEN="$(openssl rand -hex 16)"
    else
        ECS_SETUP_TOKEN="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    fi
    export ECS_SETUP_TOKEN
    generated_token=1
fi

compose_args=(up -d)
if [[ "$no_build" -eq 0 ]]; then
    compose_args+=(--build)
fi

echo "Starting ecs-controller..."
"${compose_cmd[@]}" "${compose_args[@]}"

container_name="$("${compose_cmd[@]}" ps -q ecs-controller)"
if [[ -z "$container_name" ]]; then
    echo "The ecs-controller container was not created." >&2
    exit 1
fi

health_state="starting"
for _ in {1..30}; do
    health_state="$(docker inspect --format '{{.State.Health.Status}}' "$container_name" 2>/dev/null || true)"
    if [[ "$health_state" == "healthy" ]]; then
        break
    fi
    if [[ "$health_state" == "unhealthy" || "$health_state" == "" ]]; then
        echo "Container health check failed: ${health_state:-unknown}" >&2
        "${compose_cmd[@]}" logs --tail=80 ecs-controller >&2 || true
        exit 1
    fi
    sleep 2
done

if [[ "$health_state" != "healthy" ]]; then
    echo "Timed out waiting for ecs-controller health check: $health_state" >&2
    "${compose_cmd[@]}" logs --tail=80 ecs-controller >&2 || true
    exit 1
fi

echo "ecs-controller is healthy."
echo "Open: http://127.0.0.1:43211"
if [[ "$generated_token" -eq 1 ]]; then
    echo "First-run setup token: $ECS_SETUP_TOKEN"
    echo "Save this token until initialization is complete."
else
    echo "Using ECS_SETUP_TOKEN from the environment."
fi
