#!/bin/sh
set -eu

state_dir="${ECS_UPDATE_DIR:-/update-state}"
project_dir="${ECS_PROJECT_DIR:-/workspace}"
compose_project="${ECS_COMPOSE_PROJECT_NAME:-ecs-controller}"
branch="${ECS_UPDATE_BRANCH:-main}"
request_file="$state_dir/request.json"
processing_file="$state_dir/request.processing.json"
status_file="$state_dir/status.json"
lock_dir="$state_dir/.lock"

mkdir -p "$state_dir"
rmdir "$lock_dir" 2>/dev/null || true

json_escape() {
    printf '%s' "$1" | awk 'BEGIN { ORS="" } { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\r/, ""); printf "%s\\n", $0 }'
}

write_status() {
    status="$1"
    phase="$2"
    message="$3"
    progress="${4:-0}"
    target="${5:-}"
    current="${6:-}"
    now="$(date -u +%s)"
    tmp="$status_file.tmp"
    cat >"$tmp" <<EOF
{"status":"$(json_escape "$status")","phase":"$(json_escape "$phase")","message":"$(json_escape "$message")","progress":$progress,"target_commit":"$(json_escape "$target")","current_commit":"$(json_escape "$current")","updated_at":$now}
EOF
    mv "$tmp" "$status_file"
}

read_field() {
    field="$1"
    file="$2"
    sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$file" | head -n 1
}

wait_for_controller() {
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
        container_id="$(docker compose --project-name "$compose_project" -f "$project_dir/docker-compose.yml" ps -q ecs-controller 2>/dev/null | head -n 1)"
        health="$(docker inspect --format '{{.State.Health.Status}}' "$container_id" 2>/dev/null || true)"
        if [ "$health" = healthy ]; then
            return 0
        fi
        if [ "$health" = unhealthy ]; then
            return 1
        fi
        sleep 2
    done
    return 1
}

run_update() {
    target="$(read_field target_sha "$processing_file")"
    request_id="$(read_field request_id "$processing_file")"
    current="$(git -C "$project_dir" rev-parse HEAD 2>/dev/null || true)"
    write_status queued queued "更新任务已提交" 5 "$target" "$current"

    if [ -z "$target" ]; then
        write_status error failed "更新请求缺少目标版本" 0 "$target" "$current"
        return
    fi
    if [ -n "$(git -C "$project_dir" status --porcelain 2>/dev/null || true)" ]; then
        write_status error failed "部署目录存在未提交修改，已停止更新以避免覆盖本地文件" 0 "$target" "$current"
        return
    fi

    write_status running fetching "正在从 GitHub 获取最新代码" 20 "$target" "$current"
    if ! git -C "$project_dir" fetch --depth=1 origin "$branch"; then
        write_status error failed "GitHub 代码获取失败，请检查网络或仓库权限" 0 "$target" "$current"
        return
    fi
    remote="$(git -C "$project_dir" rev-parse "origin/$branch" 2>/dev/null || true)"
    if [ "$remote" != "$target" ]; then
        write_status error failed "GitHub 版本在检查后发生变化，请重新检查更新" 0 "$target" "$current"
        return
    fi

    write_status running pulling "正在获取预构建 Docker 镜像" 50 "$target" "$current"
    export ECS_COMMIT="$target"
    export ECS_VERSION="$(printf '%s' "$target" | cut -c1-8)"
    export ECS_BUILD_DATE="$(git -C "$project_dir" show -s --format=%cI "$target" 2>/dev/null || printf '%s' unknown)"
    export ECS_IMAGE_TAG="sha-$target"
    if ! docker compose --project-name "$compose_project" -f "$project_dir/docker-compose.yml" pull ecs-controller; then
        write_status error failed "对应的预构建 Docker 镜像不存在或无法拉取，已停止更新" 0 "$target" "$current"
        return
    fi
    write_status running pulling "正在切换到目标版本" 65 "$target" "$current"
    if ! git -C "$project_dir" merge --ff-only "origin/$branch" >/dev/null 2>&1; then
        write_status error failed "本地代码无法快进到目标版本" 0 "$target" "$current"
        return
    fi
    write_status running restarting "正在重启 ECS Controller" 80 "$target" "$target"
    if ! docker compose --project-name "$compose_project" -f "$project_dir/docker-compose.yml" up -d --no-build --force-recreate ecs-controller || ! wait_for_controller; then
        git -C "$project_dir" reset --hard "$current" >/dev/null 2>&1 || true
        export ECS_COMMIT="$current"
        export ECS_VERSION="$(printf '%s' "$current" | cut -c1-8)"
        export ECS_BUILD_DATE="$(git -C "$project_dir" show -s --format=%cI "$current" 2>/dev/null || printf '%s' unknown)"
        export ECS_IMAGE_TAG="sha-$current"
        docker compose --project-name "$compose_project" -f "$project_dir/docker-compose.yml" pull ecs-controller >/dev/null 2>&1 || true
        docker compose --project-name "$compose_project" -f "$project_dir/docker-compose.yml" up -d --no-build --force-recreate ecs-controller >/dev/null 2>&1 || true
        write_status error rolled_back "服务重启失败，已尝试恢复到更新前版本" 0 "$target" "$current"
        return
    fi
    write_status success completed "更新完成，当前已运行最新版本" 100 "$target" "$target"
    rm -f "$processing_file"
}

while :; do
    if [ ! -f "$request_file" ] && [ -f "$processing_file" ]; then
        mv "$processing_file" "$request_file"
    fi
    if [ -f "$request_file" ] && mkdir "$lock_dir" 2>/dev/null; then
        mv "$request_file" "$processing_file"
        run_update || write_status error failed "更新任务异常退出" 0
        rm -f "$processing_file"
        rmdir "$lock_dir" 2>/dev/null || true
    fi
    sleep 2
done
