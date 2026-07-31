package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
)

const (
	defaultUpdateRepo   = "Kori1c/ecs-controller"
	defaultUpdateBranch = "main"
)

var commitPattern = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

type updateCheckResult struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
	} `json:"commit"`
	HTMLURL string `json:"html_url"`
}

type updateRequest struct {
	RequestID   string `json:"request_id"`
	TargetSHA   string `json:"target_sha"`
	RequestedAt int64  `json:"requested_at"`
}

func (s *Server) updateRepository() string {
	return fallback(os.Getenv("ECS_UPDATE_REPO"), defaultUpdateRepo)
}

func (s *Server) updateBranch() string {
	return fallback(os.Getenv("ECS_UPDATE_BRANCH"), defaultUpdateBranch)
}

func (s *Server) updateRepositoryURL() string {
	return "https://github.com/" + s.updateRepository()
}

func (s *Server) updateConfigured() bool {
	return strings.TrimSpace(s.UpdateDir) != ""
}

func (s *Server) checkForUpdate(w http.ResponseWriter, r *http.Request) {
	currentCommit := strings.TrimSpace(app.Commit)
	currentVersion := shortCommit(currentCommit)
	if currentVersion == "" || currentVersion == "dev" {
		currentVersion = app.Version
	}
	result := map[string]any{
		"success":          true,
		"configured":       s.updateConfigured(),
		"repository":       s.updateRepository(),
		"repository_url":   s.updateRepositoryURL(),
		"branch":           s.updateBranch(),
		"current_version":  currentVersion,
		"current_commit":   currentCommit,
		"current_url":      "",
		"build_date":       app.BuildDate,
		"update_available": false,
		"checked_at":       time.Now().UTC().Format(time.RFC3339),
	}
	if commitPattern.MatchString(currentCommit) {
		result["current_url"] = s.updateRepositoryURL() + "/commit/" + currentCommit
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", s.updateRepository(), s.updateBranch())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		s.error(w, http.StatusBadGateway, "更新检查请求创建失败")
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ecs-controller-update-check")
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		result["success"] = false
		result["message"] = "无法连接 GitHub，请检查容器网络"
		s.json(w, http.StatusOK, result)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		result["success"] = false
		result["message"] = fmt.Sprintf("GitHub 返回 HTTP %d", resp.StatusCode)
		s.json(w, http.StatusOK, result)
		return
	}
	var latest updateCheckResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&latest); err != nil || !commitPattern.MatchString(latest.SHA) {
		result["success"] = false
		result["message"] = "GitHub 返回的版本信息无效"
		s.json(w, http.StatusOK, result)
		return
	}
	result["latest"] = map[string]any{
		"version": shortCommit(latest.SHA),
		"commit":  latest.SHA,
		"message": strings.TrimSpace(strings.Split(latest.Commit.Message, "\n")[0]),
		"url":     latest.HTMLURL,
	}
	result["update_available"] = !strings.EqualFold(currentCommit, latest.SHA) && !strings.EqualFold(currentCommit, shortCommit(latest.SHA))
	if !s.updateConfigured() {
		result["message"] = "当前部署未启用 Docker 在线更新，请使用 install.sh 更新"
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) updateStatus(w http.ResponseWriter) {
	status := map[string]any{
		"status":     "idle",
		"configured": s.updateConfigured(),
	}
	if !s.updateConfigured() {
		status["message"] = "当前部署未启用 Docker 在线更新"
		s.json(w, http.StatusOK, status)
		return
	}
	path := filepath.Join(s.UpdateDir, "status.json")
	raw, err := os.ReadFile(path)
	if err == nil {
		var stored map[string]any
		if json.Unmarshal(raw, &stored) == nil {
			for key, value := range stored {
				status[key] = value
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		status["message"] = "更新状态读取失败"
	}
	s.json(w, http.StatusOK, status)
}

func (s *Server) startUpdate(w http.ResponseWriter, r *http.Request, data map[string]any) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if !s.updateConfigured() {
		s.error(w, http.StatusServiceUnavailable, "当前部署未启用 Docker 在线更新，请使用 install.sh 更新")
		return
	}
	targetSHA := strings.ToLower(strings.TrimSpace(stringValue(data["target_commit"])))
	if !commitPattern.MatchString(targetSHA) {
		s.error(w, http.StatusBadRequest, "更新版本标识无效，请重新检查更新")
		return
	}
	state := s.readUpdateState()
	if state == "queued" || state == "running" {
		s.error(w, http.StatusConflict, "已有更新任务正在执行")
		return
	}
	if _, err := os.Stat(filepath.Join(s.UpdateDir, "request.json")); err == nil {
		s.error(w, http.StatusConflict, "已有更新请求等待执行")
		return
	}
	if _, err := os.Stat(filepath.Join(s.UpdateDir, "request.processing.json")); err == nil {
		s.error(w, http.StatusConflict, "已有更新请求等待执行")
		return
	}
	if err := os.MkdirAll(s.UpdateDir, 0700); err != nil {
		s.error(w, http.StatusInternalServerError, "更新目录不可用")
		return
	}
	request := updateRequest{RequestID: randomToken(16), TargetSHA: targetSHA, RequestedAt: time.Now().Unix()}
	path := filepath.Join(s.UpdateDir, "request.json")
	temporary := path + ".tmp"
	raw, _ := json.Marshal(request)
	if err := os.WriteFile(temporary, raw, 0600); err != nil {
		s.error(w, http.StatusInternalServerError, "更新请求写入失败")
		return
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		s.error(w, http.StatusInternalServerError, "更新请求提交失败")
		return
	}
	s.json(w, http.StatusAccepted, map[string]any{"success": true, "request_id": request.RequestID, "status": "queued"})
}

func (s *Server) readUpdateState() string {
	if !s.updateConfigured() {
		return "idle"
	}
	raw, err := os.ReadFile(filepath.Join(s.UpdateDir, "status.json"))
	if err != nil {
		return "idle"
	}
	var state struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(raw, &state) != nil {
		return "idle"
	}
	return state.Status
}

func shortCommit(commit string) string {
	commit = strings.TrimSpace(commit)
	if len(commit) > 8 {
		return commit[:8]
	}
	return commit
}
