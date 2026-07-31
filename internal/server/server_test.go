package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/cloud"
	"github.com/Kori1c/ecs-controller/internal/store"
)

func TestSetupLoginAndCSRF(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	dataDir := t.TempDir()
	templatePath := filepath.Join(t.TempDir(), "template.html")
	if err := os.WriteFile(templatePath, []byte("<!doctype html>ok"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := New(st, dataDir, templatePath, "setup-token", nil)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	for _, path := range []string{"/index.php", "/index.php?action=view"} {
		resp, err := client.Get(httpSrv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("legacy page route %s status: %d", path, resp.StatusCode)
		}
		resp.Body.Close()
	}

	resp := postJSON(t, client, httpSrv.URL+"/index.php?action=setup", map[string]any{"admin_password": "correct horse battery staple", "traffic_threshold": 95}, map[string]string{"X-Setup-Token": "wrong"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong setup token status: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=setup", map[string]any{"admin_password": "correct horse battery staple", "traffic_threshold": 95}, map[string]string{"X-Setup-Token": "setup-token"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup status: %d", resp.StatusCode)
	}
	csrf := resp.Header.Get("X-CSRF-Token")
	resp.Body.Close()
	if csrf == "" {
		t.Fatal("setup did not return csrf token")
	}

	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=save_config", map[string]any{"traffic_threshold": 90, "api_interval": 600}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing csrf status: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=save_config", map[string]any{"traffic_threshold": 90, "api_interval": 600}, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("valid csrf status: %d body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()

	resp, err = client.Get(httpSrv.URL + "/index.php?action=check_login")
	if err != nil {
		t.Fatal(err)
	}
	var check map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&check)
	resp.Body.Close()
	if check["logged_in"] != true {
		t.Fatal("session was not established")
	}
	if got := resp.Header.Get("X-CSRF-Token"); got != csrf {
		t.Fatalf("check_login did not restore csrf token: got %q want %q", got, csrf)
	}

	var upload bytes.Buffer
	writer := multipart.NewWriter(&upload)
	part, err := writer.CreateFormFile("logo", "logo.png")
	if err != nil {
		t.Fatal(err)
	}
	// Minimal 1x1 PNG. The endpoint validates the detected MIME type before saving.
	if _, err := part.Write([]byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
		0x89,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, httpSrv.URL+"/index.php?action=upload_logo", &upload)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("logo upload status: %d body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()
	if _, err := os.Stat(dataDir + "/brand-logo.png"); err != nil {
		t.Fatalf("logo was not saved: %v", err)
	}
}

func TestAdminPasswordCanBeChangedFromConfig(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := New(st, t.TempDir(), "", "setup-token", nil)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp := postJSON(t, client, httpSrv.URL+"/index.php?action=setup", map[string]any{"admin_password": "start1"}, map[string]string{"X-Setup-Token": "setup-token"})
	csrf := resp.Header.Get("X-CSRF-Token")
	resp.Body.Close()
	if csrf == "" {
		t.Fatal("setup did not return csrf token")
	}

	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=save_config", map[string]any{"admin_password": "six123", "traffic_threshold": 95, "api_interval": 600}, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("password change status: %d body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()
	if !st.CheckAdminPassword("six123") || st.CheckAdminPassword("start1") {
		t.Fatal("admin password was not changed")
	}

	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=save_config", map[string]any{"admin_password": "********", "traffic_threshold": 95, "api_interval": 600}, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("masked password save status: %d body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()
	if !st.CheckAdminPassword("six123") {
		t.Fatal("masked password overwrote the current password")
	}

	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=save_config", map[string]any{"admin_password": "12345", "traffic_threshold": 95, "api_interval": 600}, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("short password status: %d body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()
}

func TestNotificationSwitchesPersistAndReadBack(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := New(st, t.TempDir(), "", "setup-token", nil)
	config := map[string]any{
		"traffic_threshold": 95,
		"api_interval":      600,
		"Notification": map[string]any{
			"email_enabled": false,
			"email":         "ops@example.com",
			"daily_enabled": true,
			"daily_time":    "01:30",
			"telegram": map[string]any{
				"enabled":     true,
				"confirm_ttl": 60,
			},
			"webhook": map[string]any{
				"enabled": true,
			},
		},
	}
	if err := srv.saveConfig(config); err != nil {
		t.Fatal(err)
	}

	settings := st.Settings()
	if settings["notify_email_enabled"] != "0" || settings["notify_tg_enabled"] != "1" || settings["notify_wh_enabled"] != "1" {
		t.Fatalf("notification switches were not normalized: email=%q telegram=%q webhook=%q", settings["notify_email_enabled"], settings["notify_tg_enabled"], settings["notify_wh_enabled"])
	}
	if settings["notify_daily_enabled"] != "1" || settings["notify_daily_time"] != "01:30" {
		t.Fatalf("daily summary settings were not normalized: enabled=%q time=%q", settings["notify_daily_enabled"], settings["notify_daily_time"])
	}
	readBack := notificationSettings(settings)
	telegram := readBack["telegram"].(map[string]any)
	webhook := readBack["webhook"].(map[string]any)
	if readBack["email_enabled"] != false || readBack["daily_enabled"] != true || readBack["daily_time"] != "01:30" || telegram["enabled"] != true || webhook["enabled"] != true {
		t.Fatalf("notification switches did not read back: %#v", readBack)
	}

	legacy := notificationSettings(map[string]string{
		"notify_email_enabled": "false",
		"notify_tg_enabled":    "true",
		"notify_wh_enabled":    "false",
	})
	legacyTelegram := legacy["telegram"].(map[string]any)
	legacyWebhook := legacy["webhook"].(map[string]any)
	if legacy["email_enabled"] != false || legacyTelegram["enabled"] != true || legacyWebhook["enabled"] != false {
		t.Fatalf("legacy notification switches were not interpreted: %#v", legacy)
	}
}

func TestSaveConfigSyncsGroupWithGeneratedKey(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := New(st, t.TempDir(), "", "setup-token", nil)
	srv.CloudFactory = func(app.Account) cloud.Client {
		return &fakeSyncClient{instances: []cloud.Instance{{ID: "i-generated", Status: "Running"}}}
	}
	if err := srv.saveConfig(map[string]any{
		"Accounts": []any{map[string]any{
			"AccessKeyId":     "ak",
			"AccessKeySecret": "sk",
			"regionId":        "cn-test",
			"maxTraffic":      200,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	groups, err := st.LoadGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].GroupKey == "" {
		t.Fatalf("generated group key was not persisted: %#v", groups)
	}
	for _, log := range st.Logs("", 20) {
		if log["message"] == "账号组同步失败: 账号组不存在" {
			t.Fatalf("sync used the pre-save empty group key: %#v", log)
		}
	}
	accounts, err := st.LoadAccounts(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].GroupKey != groups[0].GroupKey {
		t.Fatalf("synced account was not linked to the generated group: %#v", accounts)
	}
}

func TestTestAccountResolvesMaskedSecret(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SaveGroups([]app.AccountGroup{{GroupKey: "group-1", AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-hongkong"}}); err != nil {
		t.Fatal(err)
	}

	srv := New(st, t.TempDir(), "", "setup-token", nil)
	secret, err := srv.resolveMaskedAccountSecret(map[string]any{"groupKey": "group-1"}, "ak", "cn-hongkong")
	if err != nil || secret != "sk" {
		t.Fatalf("masked account secret was not restored: secret=%q err=%v", secret, err)
	}
	if _, err := srv.resolveMaskedAccountSecret(map[string]any{"groupKey": "group-1"}, "other-ak", "cn-hongkong"); err == nil {
		t.Fatal("secret was restored for a different access key")
	}
}

func TestTaskResponsePreservesFrontendCredentialFields(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateTask("task-1", "preview-1", "group-1", "cn-test", "ecs.test", map[string]any{"loginPassword": "Password123!"}); err != nil {
		t.Fatal(err)
	}
	task, err := st.GetTask("task-1")
	if err != nil {
		t.Fatal(err)
	}
	response := taskResponse(task)
	if response["loginPassword"] != "Password123!" {
		t.Fatalf("camelCase password missing: %#v", response)
	}
	if response["task_id"] != "task-1" || response["taskId"] != "task-1" {
		t.Fatalf("task aliases missing: %#v", response)
	}
}

func TestConfigDoesNotDoubleCountCDTAggregateAcrossInstances(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SaveGroups([]app.AccountGroup{{GroupKey: "group-1", AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", MaxTraffic: 200}}); err != nil {
		t.Fatal(err)
	}
	for _, instanceID := range []string{"i-1", "i-2"} {
		if err := st.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", GroupKey: "group-1", InstanceID: instanceID, TrafficUsed: 12.5, TrafficAPIStatus: "fallback_cdt", TrafficAPIMessage: "CDT aggregate", UpdatedAt: 100}); err != nil {
			t.Fatal(err)
		}
	}
	srv := New(st, t.TempDir(), "", "setup-token", nil)
	recorder := httptest.NewRecorder()
	srv.config(recorder)
	if recorder.Code != http.StatusOK {
		t.Fatalf("config status: %d", recorder.Code)
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	items, ok := response["Accounts"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("unexpected account groups: %#v", response["Accounts"])
	}
	item := items[0].(map[string]any)
	if item["usageUsed"] != 12.5 {
		t.Fatalf("CDT aggregate was double-counted: %#v", item["usageUsed"])
	}
}

type fakePreflightClient struct{ cloud.Client }

func (f *fakePreflightClient) DescribeInstanceType(context.Context, string, string) (map[string]any, error) {
	return map[string]any{"InstanceTypeId": "ecs.test", "CpuArchitecture": "X86"}, nil
}

func (f *fakePreflightClient) DescribeAvailableZones(context.Context, string, string, string) ([]map[string]any, error) {
	return []map[string]any{{"ZoneId": "zone-a", "Status": "Available"}}, nil
}

func (f *fakePreflightClient) DescribeImagesForArchitecture(context.Context, string, string, string) ([]map[string]any, error) {
	return []map[string]any{{"ImageId": "img-x86", "OSName": "Windows Server 2022"}}, nil
}

func (f *fakePreflightClient) GetSystemDiskOptions(context.Context, string, string, string) ([]map[string]any, error) {
	return []map[string]any{{"value": "cloud_essd", "label": "ESSD", "min": 40, "max": 100, "unit": "GB"}}, nil
}

type fakeSyncClient struct {
	cloud.Client
	instances []cloud.Instance
}

func (f *fakeSyncClient) DescribeInstances(context.Context, string) ([]cloud.Instance, error) {
	return f.instances, nil
}

func TestSyncGroupPreservesReleaseAndQueuesMissingInstances(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SaveGroups([]app.AccountGroup{{GroupKey: "group-1", AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", MaxTraffic: 200}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", GroupKey: "group-1", InstanceID: "i-release", InstanceStatus: "Releasing"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", GroupKey: "group-1", InstanceID: "i-missing", InstanceStatus: "Stopped"}); err != nil {
		t.Fatal(err)
	}
	srv := New(st, t.TempDir(), "", "setup-token", nil)
	srv.CloudFactory = func(app.Account) cloud.Client {
		return &fakeSyncClient{instances: []cloud.Instance{{ID: "i-release", Status: "Running", PublicIP: "203.0.113.20"}}}
	}
	count, err := srv.syncGroup("group-1")
	if err != nil || count != 1 {
		t.Fatalf("sync result: %d %v", count, err)
	}
	accounts, err := st.LoadAccounts(false)
	if err != nil {
		t.Fatal(err)
	}
	var release, missing *app.Account
	for i := range accounts {
		switch accounts[i].InstanceID {
		case "i-release":
			release = &accounts[i]
		case "i-missing":
			missing = &accounts[i]
		}
	}
	if release == nil || release.InstanceStatus != "Releasing" {
		t.Fatalf("release state was resurrected: %#v", release)
	}
	if missing == nil || missing.InstanceStatus != "Releasing" {
		t.Fatalf("missing instance was not queued: %#v", missing)
	}
	job, err := st.ClaimJob(time.Minute)
	if err != nil || job == nil || job.EntityKey != fmt.Sprint(missing.ID) {
		t.Fatalf("missing cleanup job: %#v %v", job, err)
	}
}

func TestPreviewUsesDynamicArchitectureZoneDiskAndWindowsPort(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SaveGroups([]app.AccountGroup{{GroupKey: "group-1", AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", Remark: "test"}}); err != nil {
		t.Fatal(err)
	}
	srv := New(st, t.TempDir(), "", "setup-token", nil)
	srv.CloudFactory = func(app.Account) cloud.Client { return &fakePreflightClient{} }
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp := postJSON(t, client, httpSrv.URL+"/index.php?action=setup", map[string]any{"admin_password": "correct horse battery staple"}, map[string]string{"X-Setup-Token": "setup-token"})
	csrf := resp.Header.Get("X-CSRF-Token")
	resp.Body.Close()
	if csrf == "" {
		t.Fatal("setup did not return csrf token")
	}
	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=preview_ecs_create", map[string]any{
		"accountGroupKey": "group-1", "instanceType": "ecs.test", "osKey": "windows_2022", "zoneId": "zone-a",
		"systemDiskCategory": "cloud_essd_entry", "systemDiskSize": 20, "publicIpMode": "ecs_public_ip", "clientCidrIp": "192.0.2.10/32",
	}, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("preview status: %d body=%s", resp.StatusCode, body)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	summary, ok := result["summary"].(map[string]any)
	if !ok || summary["imageId"] != "img-x86" || summary["loginPort"] != float64(3389) || summary["zoneId"] != "zone-a" {
		t.Fatalf("dynamic preview fields missing: %#v", result)
	}
	disk, ok := summary["systemDisk"].(map[string]any)
	if !ok || disk["category"] != "cloud_essd" || disk["size"] != float64(40) || disk["min"] != float64(40) {
		t.Fatalf("dynamic disk fields missing: %#v", summary["systemDisk"])
	}
}

func TestOnlineUpdateRequestRequiresUpdaterAndPersistsTarget(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := New(st, t.TempDir(), "", "setup-token", nil)
	request := httptest.NewRequest(http.MethodPost, "/index.php?action=start_update", nil)
	recorder := httptest.NewRecorder()
	srv.startUpdate(recorder, request, map[string]any{"target_commit": strings.Repeat("a", 40)})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured updater status: %d", recorder.Code)
	}

	srv.UpdateDir = t.TempDir()
	recorder = httptest.NewRecorder()
	srv.startUpdate(recorder, request, map[string]any{"target_commit": strings.Repeat("b", 40)})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("update request status: %d body=%s", recorder.Code, recorder.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(srv.UpdateDir, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), strings.Repeat("b", 40)) {
		t.Fatalf("target commit was not persisted: %s", raw)
	}
}

func postJSON(t *testing.T, client *http.Client, endpoint string, value map[string]any, headers map[string]string) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(value)
	req, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
