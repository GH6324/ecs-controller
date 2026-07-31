package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/cloud"
	"github.com/Kori1c/ecs-controller/internal/notify"
	"github.com/Kori1c/ecs-controller/internal/store"
)

type Server struct {
	Store        *store.Store
	Cloud        cloud.Client
	CloudFactory func(app.Account) cloud.Client
	DataDir      string
	Template     string
	SetupToken   string
	CookieSecure bool
	UpdateDir    string
	Log          *log.Logger
	mu           sync.Mutex
	updateMu     sync.Mutex
	previews     map[string]map[string]any
}

func New(st *store.Store, dataDir, templatePath, setupToken string, client cloud.Client) *Server {
	if setupToken == "" {
		setupToken = randomToken(24)
		log.Printf("ECS_SETUP_TOKEN 未设置，本次初始化 token: %s", setupToken)
	}
	return &Server{Store: st, DataDir: dataDir, Template: templatePath, SetupToken: setupToken, Cloud: client, Log: log.Default(), previews: map[string]map[string]any{}}
}

func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.handle) }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		s.json(w, 200, map[string]any{"ok": true, "initialized": s.Store.IsInitialized()})
		return
	}
	action := r.URL.Query().Get("action")
	if action == "" && (r.URL.Path == "/" || r.URL.Path == "/index.html" || r.URL.Path == "/index.php") {
		s.serveTemplate(w)
		return
	}
	if action == "" && strings.HasPrefix(r.URL.Path, "/static/") {
		http.FileServer(http.Dir(filepath.Dir(s.Template))).ServeHTTP(w, r)
		return
	}
	if action == "" {
		http.NotFound(w, r)
		return
	}

	switch action {
	case "view":
		s.serveTemplate(w)
	case "check_init":
		s.checkInit(w)
	case "setup":
		s.setup(w, r)
	case "login":
		s.login(w, r)
	case "check_login":
		s.checkLogin(w, r)
	case "brand_logo":
		s.brandLogo(w)
	default:
		if !s.authenticated(r) {
			s.error(w, http.StatusForbidden, "请先登录后再操作")
			return
		}
		if s.mutating(action) && !s.csrfOK(w, r) {
			return
		}
		s.authenticatedAction(w, r, action)
	}
}

func (s *Server) serveTemplate(w http.ResponseWriter) {
	data, err := os.ReadFile(s.Template)
	if err != nil {
		s.error(w, 500, "模板读取失败")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
func (s *Server) checkInit(w http.ResponseWriter) {
	s.json(w, 200, map[string]any{"initialized": s.Store.IsInitialized(), "brand": map[string]any{"logo_url": s.Store.GetSetting("app_logo_url", "")}})
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if s.Store.IsInitialized() {
		s.error(w, http.StatusForbidden, "系统已完成初始化")
		return
	}
	if r.Header.Get("X-Setup-Token") != s.SetupToken {
		s.error(w, http.StatusForbidden, "初始化 token 无效")
		return
	}
	data, err := readJSON(r)
	if err != nil {
		s.error(w, 400, err.Error())
		return
	}
	password := stringValue(data["admin_password"])
	if len(password) < 6 {
		s.error(w, 400, "管理员密码至少需要 6 个字符")
		return
	}
	threshold := number(data["traffic_threshold"], 95)
	if threshold < 1 || threshold > 100 {
		s.error(w, 400, "流量阈值必须在 1 到 100 之间")
		return
	}
	if err := s.Store.SetAdminPassword(password); err != nil {
		s.error(w, 500, "初始化失败")
		return
	}
	data["traffic_threshold"] = threshold
	if err := s.saveConfig(data); err != nil {
		s.error(w, 500, "初始化配置保存失败")
		return
	}
	s.createSession(w)
	s.json(w, 200, map[string]any{"success": true})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if s.Store.RecentLoginFailures(ip, time.Minute) >= 10 {
		s.error(w, 429, "登录尝试过于频繁")
		return
	}
	data, err := readJSON(r)
	if err != nil {
		s.error(w, 400, err.Error())
		return
	}
	if !s.Store.CheckAdminPassword(stringValue(data["password"])) {
		s.Store.RecordLoginFailure(ip)
		s.json(w, 200, map[string]any{"success": false, "message": "密码错误"})
		return
	}
	s.Store.ClearLoginFailures(ip)
	s.createSession(w)
	s.json(w, 200, map[string]any{"success": true})
}

func (s *Server) checkLogin(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.session(r)
	if ok && csrf != "" {
		// A page reload loses the in-memory token. Expose the persisted session
		// token through the same header used by login and setup.
		w.Header().Set("X-CSRF-Token", csrf)
	}
	s.json(w, 200, map[string]any{"logged_in": ok, "csrf_token": csrf})
}
func (s *Server) brandLogo(w http.ResponseWriter) {
	for _, ext := range []string{"png", "jpg", "webp"} {
		p := filepath.Join(s.DataDir, "brand-logo."+ext)
		if st, err := os.Stat(p); err == nil && st.Size() <= 2<<20 {
			w.Header().Set("Content-Type", mime.TypeByExtension("."+ext))
			w.Header().Set("Cache-Control", "public,max-age=86400")
			data, readErr := os.ReadFile(p)
			if readErr != nil {
				http.Error(w, "not found", 404)
				return
			}
			_, _ = w.Write(data)
			return
		}
	}
	http.NotFound(w, nil)
}

func (s *Server) authenticatedAction(w http.ResponseWriter, r *http.Request, action string) {
	// Multipart uploads must be parsed before anything reads r.Body. JSON
	// decoding a multipart request would consume the file stream.
	if action == "upload_logo" {
		s.uploadLogo(w, r)
		return
	}
	data, _ := readJSON(r)
	switch action {
	case "get_status":
		s.status(w)
	case "get_config":
		s.config(w)
	case "check_update":
		s.checkForUpdate(w, r)
	case "get_update_status":
		s.updateStatus(w)
	case "save_config":
		if err := s.saveConfig(data); err != nil {
			s.error(w, 400, err.Error())
		} else {
			s.json(w, 200, map[string]any{"success": true})
		}
	case "start_update":
		s.startUpdate(w, r, data)
	case "get_logs":
		s.json(w, 200, map[string]any{"data": s.Store.Logs(r.URL.Query().Get("tab"), 20)})
	case "clear_logs":
		if err := s.Store.ClearLogs(stringValue(data["tab"])); err != nil {
			s.error(w, 500, "清空失败")
		} else {
			s.json(w, 200, map[string]any{"success": true})
		}
	case "get_history":
		id := int64(number(r.URL.Query().Get("id"), 0))
		if _, err := s.Store.Account(id, false); err != nil {
			s.error(w, 404, "账号不存在")
			return
		}
		history, err := s.Store.AccountHistory(id)
		if err != nil {
			s.error(w, 500, "历史流量读取失败")
			return
		}
		s.json(w, 200, map[string]any{"data": history})
	case "logout":
		s.logout(w, r)
	case "get_all_instances":
		if r.URL.Query().Get("sync") == "1" {
			groups, _ := s.Store.LoadGroups()
			for _, group := range groups {
				if _, err := s.syncGroup(group.GroupKey); err != nil {
					s.Store.AddLog("warning", "手动同步失败: "+err.Error())
				}
			}
		}
		s.status(w)
	case "preview_ecs_create":
		s.preview(w, r, data)
	case "get_ecs_disk_options":
		s.diskOptions(w, r, data)
	case "create_ecs":
		s.createTask(w, r, data)
	case "get_ecs_create_task":
		s.task(w, r)
	case "control_instance":
		s.control(w, data)
	case "delete_instance":
		s.deleteInstance(w, data)
	case "replace_instance_ip":
		s.replaceIP(w, data)
	case "refresh_account", "sync_account_group", "restore_schedule_block":
		if action == "refresh_account" {
			s.refreshAccount(w, data)
			return
		}
		if action == "sync_account_group" {
			s.syncGroupAction(w, data)
			return
		}
		if action == "restore_schedule_block" {
			if err := s.Store.SetGroupScheduleBlocked(stringValue(data["groupKey"]), false); err != nil {
				s.error(w, 500, "恢复定时任务失败")
				return
			}
			s.json(w, 200, map[string]any{"success": true})
			return
		}
		s.json(w, 200, map[string]any{"success": true})
	case "fetch_instances":
		s.fetchInstances(w, data)
	case "test_account":
		s.testAccount(w, data)
	case "send_test_email", "send_test_telegram", "send_test_webhook":
		s.testNotification(w, action, data)
	default:
		s.error(w, 404, "未知操作")
	}
}

func (s *Server) config(w http.ResponseWriter) {
	settings := s.Store.Settings()
	groups, _ := s.Store.LoadGroups()
	accounts, _ := s.Store.LoadAccounts(false)
	type metric struct {
		used         float64
		fallbackUsed float64
		hasFallback  bool
		count        int
		updated      int64
		status       string
		message      string
		accountID    int64
	}
	metrics := map[string]*metric{}
	for _, account := range accounts {
		key := account.GroupKey
		if key == "" {
			key = account.AccessKeyID + "|" + account.RegionID
		}
		m := metrics[key]
		if m == nil {
			m = &metric{status: "ok"}
			metrics[key] = m
		}
		if account.TrafficAPIStatus == "fallback_cdt" {
			// CDT is aggregated per AK/region, so repeated instance records must
			// not be summed into the group total.
			m.hasFallback = true
			if account.TrafficUsed > m.fallbackUsed {
				m.fallbackUsed = account.TrafficUsed
			}
		} else {
			m.used += account.TrafficUsed
		}
		m.count++
		if account.UpdatedAt > m.updated {
			m.updated = account.UpdatedAt
		}
		if account.TrafficAPIStatus != "" && account.TrafficAPIStatus != "ok" {
			m.status = account.TrafficAPIStatus
			m.message = account.TrafficAPIMessage
		}
		if m.accountID == 0 {
			m.accountID = account.ID
		}
	}
	for _, m := range metrics {
		if m.hasFallback {
			m.used = m.fallbackUsed
		}
	}
	result := map[string]any{"admin_password": "********", "admin_password_set": s.Store.IsInitialized(), "traffic_threshold": numberString(settings["traffic_threshold"], 95), "shutdown_mode": fallback(settings["shutdown_mode"], "KeepCharging"), "threshold_action": fallback(settings["threshold_action"], "stop_and_notify"), "keep_alive": settings["keep_alive"] == "1", "monthly_auto_start": settings["monthly_auto_start"] == "1", "api_interval": numberString(settings["api_interval"], 600), "enable_billing": settings["enable_billing"] == "1", "AppBrand": map[string]any{"logo_url": settings["app_logo_url"]}, "Notification": notificationSettings(settings), "Ddns": map[string]any{"enabled": settings["ddns_enabled"] == "1", "provider": fallback(settings["ddns_provider"], "cloudflare"), "domain": settings["ddns_domain"], "cloudflare": map[string]any{"zone_id": settings["ddns_cf_zone_id"], "token": masked(settings["ddns_cf_token"]), "proxied": settings["ddns_cf_proxied"] == "1"}}, "Accounts": []any{}}
	items := result["Accounts"].([]any)
	for _, g := range groups {
		m := metrics[g.GroupKey]
		used := 0.0
		count := 0
		updated := int64(0)
		trafficStatus := "ok"
		trafficMessage := ""
		scope := "instance"
		var billing map[string]any
		if m != nil {
			used, count, updated, trafficStatus, trafficMessage = m.used, m.count, m.updated, m.status, m.message
			scope = trafficScope(trafficStatus)
			if m.accountID > 0 {
				cycle := time.Now().Format("2006-01")
				if cdtUsed, ok := s.getCachedCDTTraffic(g, m.accountID, cycle); ok {
					// The account list intentionally shows CDT's account/region
					// aggregate, while instance cards show CMS per-instance data.
					used = cdtUsed
					trafficStatus = "ok"
					trafficMessage = ""
					scope = "account"
				}
				billing = map[string]any{}
				if cached, ok := s.Store.GetBillingCache(m.accountID, "balance", "", 6*time.Hour); ok {
					billing["balance"] = cached["balance"]
					billing["currency"] = cached["currency"]
					if cached["error"] != nil {
						billing["error"] = cached["error"]
					}
				}
				if cached, ok := s.Store.GetBillingCache(m.accountID, "bill_overview", cycle, 6*time.Hour); ok {
					billing["monthly_cost"] = cached["monthly_cost"]
					if billing["currency"] == nil || billing["currency"] == "" {
						billing["currency"] = cached["currency"]
					}
					if cached["error"] != nil {
						billing["error"] = cached["error"]
					}
				}
				if cached, ok := s.Store.GetBillingCache(m.accountID, "instance_bill", cycle, 6*time.Hour); ok && len(billing) == 0 {
					billing = cached
				}
				if len(billing) == 0 {
					billing = nil
				}
			}
		}
		if billing == nil {
			billing = map[string]any{"monthly_cost": nil, "balance": nil, "currency": map[bool]string{true: "USD", false: "CNY"}[g.SiteType == "international"], "last_updated": nil}
		}
		billing["enabled"] = settings["enable_billing"] == "1"
		if trafficStatus == "error" {
			billing["error"] = "流量接口异常，费用数据可能延迟"
		}
		usagePercent := 0.0
		if g.MaxTraffic > 0 {
			usagePercent = used / g.MaxTraffic * 100
		}
		items = append(items, map[string]any{"AccessKeyId": g.AccessKeyID, "AccessKeySecret": "********", "AccessKeySecretSet": g.AccessKeySecret != "", "regionId": g.RegionID, "maxTraffic": g.MaxTraffic, "remark": g.Remark, "siteType": g.SiteType, "groupKey": g.GroupKey, "scheduleEnabled": g.ScheduleEnabled, "scheduleStartEnabled": g.ScheduleStartEnabled, "scheduleStopEnabled": g.ScheduleStopEnabled, "startTime": g.StartTime, "stopTime": g.StopTime, "scheduleBlockedByTraffic": g.ScheduleBlockedByTraffic, "usageUsed": used, "usageRemaining": maxFloat(g.MaxTraffic-used, 0), "usagePercent": usagePercent, "instanceCount": count, "usageLastUpdated": time.Unix(updated, 0).Format("2006-01-02 15:04:05"), "trafficStatus": trafficStatus, "trafficMessage": trafficMessage, "trafficScope": scope, "billing": billing})
	}
	result["Accounts"] = items
	s.json(w, 200, result)
}

func (s *Server) getCachedCDTTraffic(group app.AccountGroup, accountID int64, cycle string) (float64, bool) {
	const cacheAge = 5 * time.Minute
	if cached, ok := s.Store.GetBillingCache(accountID, "cdt_traffic", cycle, cacheAge); ok {
		return numberFloat(cached["traffic"]), true
	}
	client := s.Cloud
	if s.CloudFactory != nil {
		client = s.CloudFactory(app.Account{AccessKeyID: group.AccessKeyID, AccessKeySecret: group.AccessKeySecret, RegionID: group.RegionID, SiteType: group.SiteType})
	}
	if client == nil {
		return 0, false
	}
	traffic, err := client.GetTraffic(rctx(), group.RegionID)
	if err != nil {
		return 0, false
	}
	_ = s.Store.SetBillingCache(accountID, "cdt_traffic", cycle, map[string]any{"traffic": traffic})
	return traffic, true
}

func (s *Server) status(w http.ResponseWriter) {
	accounts, _ := s.Store.LoadAccounts(false)
	data := make([]map[string]any, 0)
	for _, a := range accounts {
		if a.InstanceID == "" {
			continue
		}
		percent := 0.0
		if a.MaxTraffic > 0 {
			percent = a.TrafficUsed / a.MaxTraffic * 100
		}
		label := a.Remark
		if label == "" {
			label = a.AccessKeyID
		}
		data = append(data, map[string]any{"id": a.ID, "accountId": a.ID, "instanceId": a.InstanceID, "instanceName": a.InstanceName, "instanceType": a.InstanceType, "cpu": a.CPU, "memory": a.Memory, "osName": a.OSName, "region": a.RegionID, "regionId": a.RegionID, "regionName": a.RegionID, "status": a.InstanceStatus, "instanceStatus": a.InstanceStatus, "publicIp": a.PublicIP, "privateIp": a.PrivateIP, "trafficUsed": a.TrafficUsed, "flow_used": a.TrafficUsed, "flow_total": a.MaxTraffic, "percentageOfUse": percent, "rate95": percent >= float64(numberString(s.Store.GetSetting("traffic_threshold", ""), 95)), "maxTraffic": a.MaxTraffic, "remark": a.Remark, "accountLabel": label + " / " + a.RegionID, "groupKey": a.GroupKey, "healthStatus": a.HealthStatus, "trafficStatus": a.TrafficAPIStatus, "trafficMessage": a.TrafficAPIMessage, "trafficScope": trafficScope(a.TrafficAPIStatus), "internetMaxBandwidthOut": a.InternetBandwidth, "publicIpMode": a.PublicIPMode, "eipAllocationId": a.EIPAllocationID, "eipAddress": a.EIPAddress, "eipManaged": a.EIPManaged, "operationLocked": a.IsDeleted == 1})
	}
	s.json(w, 200, map[string]any{"data": data, "system_last_run": s.Store.LastRun(), "sync_interval": numberString(s.Store.GetSetting("api_interval", ""), 600), "sensitive_visible": true})
}

func trafficScope(status string) string {
	if status == "fallback_cdt" {
		return "account"
	}
	return "instance"
}

func (s *Server) saveConfig(data map[string]any) error {
	threshold := number(data["traffic_threshold"], 95)
	if threshold < 1 || threshold > 100 {
		return fmt.Errorf("流量阈值必须在 1 到 100 之间")
	}
	interval := number(data["api_interval"], 600)
	if interval < 30 || interval > 86400 {
		return fmt.Errorf("API 间隔必须在 30 到 86400 秒之间")
	}
	if password := stringValue(data["admin_password"]); password != "" && password != "********" {
		if err := s.Store.SetAdminPassword(password); err != nil {
			return err
		}
	}
	for key, value := range map[string]any{"traffic_threshold": threshold, "shutdown_mode": fallback(stringValue(data["shutdown_mode"]), "KeepCharging"), "threshold_action": fallback(stringValue(data["threshold_action"]), "stop_and_notify"), "keep_alive": bool01(data["keep_alive"]), "monthly_auto_start": bool01(data["monthly_auto_start"]), "api_interval": interval, "enable_billing": bool01(data["enable_billing"])} {
		if err := s.Store.SetSetting(key, fmt.Sprint(value)); err != nil {
			return err
		}
	}
	if brand, ok := data["AppBrand"].(map[string]any); ok {
		_ = s.Store.SetSetting("app_logo_url", stringValue(brand["logo_url"]))
	}
	if ddns, ok := data["Ddns"].(map[string]any); ok {
		_ = s.Store.SetSetting("ddns_enabled", bool01(ddns["enabled"]))
		_ = s.Store.SetSetting("ddns_provider", stringValue(ddns["provider"]))
		_ = s.Store.SetSetting("ddns_domain", stringValue(ddns["domain"]))
		if cf, ok := ddns["cloudflare"].(map[string]any); ok {
			_ = s.Store.SetSetting("ddns_cf_zone_id", stringValue(cf["zone_id"]))
			_ = s.Store.SetSetting("ddns_cf_proxied", bool01(cf["proxied"]))
			if err := s.saveSecret("ddns_cf_token", stringValue(cf["token"])); err != nil {
				return err
			}
		}
	}
	if notify, ok := data["Notification"].(map[string]any); ok {
		for key, value := range map[string]any{"notify_email_enabled": bool01(notify["email_enabled"]), "notify_email": notify["email"], "notify_host": notify["host"], "notify_port": number(notify["port"], 465), "notify_username": notify["username"], "notify_secure": notify["secure"], "notify_daily_enabled": bool01(notify["daily_enabled"]), "notify_daily_time": fallback(stringValue(notify["daily_time"]), "00:00")} {
			if err := s.Store.SetSetting(key, fmt.Sprint(value)); err != nil {
				return err
			}
		}
		if err := s.saveSecret("notify_password", stringValue(notify["password"])); err != nil {
			return err
		}
		if tg, ok := notify["telegram"].(map[string]any); ok {
			for key, value := range map[string]any{"notify_tg_enabled": bool01(tg["enabled"]), "notify_tg_chat_id": tg["chat_id"], "notify_tg_proxy_type": tg["proxy_type"], "notify_tg_proxy_url": tg["proxy_url"], "notify_tg_proxy_ip": tg["proxy_ip"], "notify_tg_proxy_port": tg["proxy_port"], "notify_tg_proxy_user": tg["proxy_user"], "notify_tg_allowed_user_ids": tg["allowed_user_ids"], "notify_tg_confirm_ttl": maxInt(number(tg["confirm_ttl"], 60), 30)} {
				if err := s.Store.SetSetting(key, fmt.Sprint(value)); err != nil {
					return err
				}
			}
			if err := s.saveSecret("notify_tg_token", stringValue(tg["token"])); err != nil {
				return err
			}
			if err := s.saveSecret("notify_tg_proxy_pass", stringValue(tg["proxy_pass"])); err != nil {
				return err
			}
		}
		if webhook, ok := notify["webhook"].(map[string]any); ok {
			for key, value := range map[string]any{"notify_wh_enabled": bool01(webhook["enabled"]), "notify_wh_url": webhook["url"], "notify_wh_method": webhook["method"], "notify_wh_request_type": webhook["request_type"], "notify_wh_headers": webhook["headers"], "notify_wh_body": webhook["body"]} {
				if err := s.Store.SetSetting(key, fmt.Sprint(value)); err != nil {
					return err
				}
			}
		}
	}
	if raw, ok := data["Accounts"].([]any); ok {
		groups := make([]app.AccountGroup, 0, len(raw))
		for _, v := range raw {
			b, _ := json.Marshal(v)
			var g app.AccountGroup
			if json.Unmarshal(b, &g) == nil {
				if g.AccessKeySecret == "********" {
					if old, _ := s.Store.LoadGroups(); old != nil {
						for _, o := range old {
							if o.GroupKey == g.GroupKey {
								g.AccessKeySecret = o.AccessKeySecret
							}
						}
					}
				}
				if g.AccessKeyID != "" && g.RegionID != "" {
					if g.MaxTraffic <= 0 {
						g.MaxTraffic = 200
					}
					groups = append(groups, g)
				}
			}
		}
		if err := s.Store.SaveGroups(groups); err != nil {
			return err
		}
		// SaveGroups fills in derived keys and persists encrypted secrets on a
		// copy, so reload the canonical groups before applying or syncing them.
		groups, err := s.Store.LoadGroups()
		if err != nil {
			return err
		}
		beforeAccounts, _ := s.Store.LoadAccounts(false)
		removedAccounts, err := s.Store.RemoveAccountsOutsideGroups(groups)
		if err != nil {
			return err
		}
		for _, account := range removedAccounts {
			if s.Store.GetSetting("ddns_enabled", "0") != "1" {
				break
			}
			_ = s.Store.EnqueueJob(randomToken(16), "delete_ddns", strconv.FormatInt(account.ID, 10), map[string]any{"account": ddnsPayloadAccount(account), "before": ddnsPayloadAccounts(beforeAccounts)})
		}
		if s.Store.GetSetting("ddns_enabled", "0") == "1" {
			// The monitor will reconcile current records and remove stale names
			// on its next pass after a configuration change.
			_ = s.Store.SetSetting("last_ddns_reconcile", "0")
		}
		for _, group := range groups {
			if err := s.Store.ApplyGroupSettings(group); err != nil {
				return err
			}
			if s.Cloud != nil || s.CloudFactory != nil {
				if _, syncErr := s.syncGroup(group.GroupKey); syncErr != nil {
					s.Store.AddLog("warning", "账号组同步失败: "+syncErr.Error())
				}
			}
		}
	}
	return nil
}

func ddnsPayloadAccount(account app.Account) map[string]any {
	return map[string]any{"GroupKey": account.GroupKey, "AccessKeyID": account.AccessKeyID, "RegionID": account.RegionID, "InstanceID": account.InstanceID, "Remark": account.Remark, "InstanceName": account.InstanceName}
}

func ddnsPayloadAccounts(accounts []app.Account) []map[string]any {
	result := make([]map[string]any, 0, len(accounts))
	for _, account := range accounts {
		result = append(result, ddnsPayloadAccount(account))
	}
	return result
}

func (s *Server) preview(w http.ResponseWriter, r *http.Request, data map[string]any) {
	id := randomToken(12)
	groupKey := stringValue(data["accountGroupKey"])
	if groupKey == "" {
		s.error(w, 400, "请选择用于创建 ECS 的账号")
		return
	}
	instanceType := stringValue(data["instanceType"])
	if instanceType == "" {
		instanceType = "ecs.e-c4m1.large"
	}
	groups, _ := s.Store.LoadGroups()
	var group *app.AccountGroup
	for i := range groups {
		if groups[i].GroupKey == groupKey {
			group = &groups[i]
			break
		}
	}
	if group == nil {
		s.error(w, 400, "账号组不存在")
		return
	}
	regionID := stringValue(data["regionId"])
	if regionID == "" {
		regionID = group.RegionID
	}
	if regionID == "" {
		s.error(w, 400, "请选择区域")
		return
	}
	osKey := stringValue(data["osKey"])
	if osKey == "" {
		osKey = "debian_12"
	}
	publicMode := stringValue(data["publicIpMode"])
	if publicMode == "" {
		publicMode = "ecs_public_ip"
	}
	if publicMode != "ecs_public_ip" && publicMode != "eip" {
		s.error(w, 400, "公网 IP 类型无效")
		return
	}
	loginPort := loginPortForOS(osKey)
	name := stringValue(data["instanceName"])
	if name == "" {
		name = "launch-" + time.Now().Format("20060102-150405")
	}
	diskCategory := stringValue(data["systemDiskCategory"])
	if diskCategory == "" {
		diskCategory = "cloud_essd_entry"
	}
	diskSize := number(data["systemDiskSize"], 20)
	bandwidth := number(data["internetMaxBandwidthOut"], 10)
	if diskSize <= 0 {
		diskSize = 20
	}
	if bandwidth < 1 {
		bandwidth = 1
	}
	data["accountGroupKey"], data["regionId"], data["instanceType"], data["osKey"] = groupKey, regionID, instanceType, osKey
	data["instanceName"], data["publicIpMode"], data["systemDiskCategory"], data["systemDiskSize"], data["internetMaxBandwidthOut"] = name, publicMode, diskCategory, diskSize, bandwidth
	data["loginPort"] = loginPort
	data["loginUser"] = loginUser(osKey)
	if stringValue(data["zoneId"]) == "" {
		data["zoneId"] = "待由云 API 选择"
	}
	if stringValue(data["clientCidrIp"]) == "" {
		ip := remoteIP(r)
		if ip == "" || ip == "::1" {
			ip = "127.0.0.1"
		}
		suffix := "/32"
		if strings.Contains(ip, ":") {
			suffix = "/128"
		}
		data["clientCidrIp"] = ip + suffix
	}
	if _, _, cidrErr := net.ParseCIDR(stringValue(data["clientCidrIp"])); cidrErr != nil {
		s.error(w, 400, "客户端来源 CIDR 无效")
		return
	}
	osLabel, imageID := osInfo(osKey)
	warnings := []any{"Go 版本已改为异步创建；请确认安全组来源和按量费用后继续"}
	previewClient := s.Cloud
	if s.CloudFactory != nil {
		previewClient = s.CloudFactory(app.Account{AccessKeyID: group.AccessKeyID, AccessKeySecret: group.AccessKeySecret, RegionID: group.RegionID, SiteType: group.SiteType})
	}
	if previewClient != nil {
		preflight, ok := previewClient.(cloud.PreflightClient)
		if !ok {
			s.error(w, 503, "当前云客户端不支持 ECS 创建预检")
			return
		}
		typeInfo, typeErr := preflight.DescribeInstanceType(r.Context(), regionID, instanceType)
		if typeErr != nil {
			s.error(w, 400, "实例规格预检失败: "+typeErr.Error())
			return
		}
		architecture := normalizeArchitecture(stringValue(typeInfo["CpuArchitecture"]))
		zones, zoneErr := preflight.DescribeAvailableZones(r.Context(), regionID, instanceType, diskCategory)
		if zoneErr != nil || len(zones) == 0 {
			if zoneErr == nil {
				zoneErr = fmt.Errorf("没有可用区库存")
			}
			s.error(w, 400, "可用区预检失败: "+zoneErr.Error())
			return
		}
		requestedZone := stringValue(data["zoneId"])
		zoneWasRequested := requestedZone != "" && requestedZone != "待由云 API 选择"
		if requestedZone == "" || requestedZone == "待由云 API 选择" {
			requestedZone = firstMapString(zones, "ZoneId", "zoneId")
		}
		if requestedZone == "" {
			s.error(w, 400, "云 API 未返回可用区")
			return
		}
		if zoneWasRequested && !containsMapValue(zones, requestedZone, "ZoneId", "zoneId") {
			s.error(w, 400, "所选可用区没有当前规格库存")
			return
		}
		data["zoneId"] = requestedZone
		var images []map[string]any
		var imageErr error
		if imageProvider, ok := previewClient.(interface {
			DescribeImagesForArchitecture(context.Context, string, string, string) ([]map[string]any, error)
		}); ok {
			images, imageErr = imageProvider.DescribeImagesForArchitecture(r.Context(), regionID, osKey, architecture)
		} else {
			imageProvider, imageOK := previewClient.(interface {
				DescribeImages(context.Context, string, string) ([]map[string]any, error)
			})
			if imageOK {
				images, imageErr = imageProvider.DescribeImages(r.Context(), regionID, osKey)
			} else {
				imageErr = fmt.Errorf("云客户端不支持镜像查询")
			}
		}
		if imageErr != nil || len(images) == 0 {
			if imageErr == nil {
				imageErr = fmt.Errorf("未找到匹配的可用系统镜像")
			}
			s.error(w, 400, "系统镜像预检失败: "+imageErr.Error())
			return
		}
		if explicitImage := stringValue(data["imageId"]); explicitImage != "" {
			imageID = explicitImage
		} else {
			imageID = firstMapString(images, "ImageId", "imageId")
		}
		if imageID == "" {
			s.error(w, 400, "镜像预检未返回 ImageId")
			return
		}
		if options, diskErr := preflight.GetSystemDiskOptions(r.Context(), regionID, requestedZone, instanceType); diskErr != nil {
			s.error(w, 400, "系统盘预检失败: "+diskErr.Error())
			return
		} else if len(options) > 0 {
			selected := selectDiskOption(options, diskCategory)
			diskCategory = stringValue(selected["value"])
			minSize, maxSize := number(selected["min"], 20), number(selected["max"], 32768)
			if diskSize < minSize {
				diskSize = minSize
			}
			if diskSize > maxSize {
				diskSize = maxSize
			}
			data["systemDiskMin"], data["systemDiskMax"] = minSize, maxSize
		} else {
			s.error(w, 400, "当前规格没有可用系统盘类型")
			return
		}
	} else if stringValue(data["imageId"]) != "" {
		imageID = stringValue(data["imageId"])
	}
	data["zoneId"], data["imageId"], data["systemDiskCategory"], data["systemDiskSize"] = stringValue(data["zoneId"]), imageID, diskCategory, diskSize
	data["_previewCreatedAt"] = time.Now().Unix()
	s.mu.Lock()
	s.previews[id] = data
	s.mu.Unlock()
	minDisk, maxDisk := number(data["systemDiskMin"], 20), number(data["systemDiskMax"], 32768)
	summary := map[string]any{"account": map[string]any{"label": group.Remark, "groupKey": group.GroupKey, "accessKeyId": maskAccessKey(group.AccessKeyID)}, "regionId": data["regionId"], "zoneId": data["zoneId"], "instanceType": instanceType, "instanceName": name, "osKey": osKey, "osLabel": osLabel, "imageId": imageID, "loginUser": loginUser(osKey), "loginPort": loginPort, "clientCidrIp": data["clientCidrIp"], "systemDisk": map[string]any{"category": diskCategory, "size": diskSize, "min": minDisk, "max": maxDisk, "unit": "GB"}, "network": map[string]any{"vpc": map[string]any{"name": "ecs-controller", "cidr": "192.168.0.0/16"}, "vswitch": map[string]any{"name": "ecs-controller", "cidr": "192.168.0.0/24"}, "securityGroup": map[string]any{"name": "ecs-controller", "cidr": stringValue(data["clientCidrIp"]), "rules": []string{fmt.Sprintf("TCP %d / %s", loginPort, stringValue(data["clientCidrIp"]))}}}, "internetMaxBandwidthOut": bandwidth, "publicIpMode": publicMode, "publicIpModeLabel": map[string]string{"eip": "EIP 弹性公网 IP", "ecs_public_ip": "ECS 普通公网 IP"}[publicMode], "accountGroupKey": groupKey}
	if summary["publicIpModeLabel"] == "" {
		summary["publicIpModeLabel"] = publicMode
	}
	s.json(w, 200, map[string]any{"success": true, "previewId": id, "summary": summary, "pricing": map[string]any{"message": "价格预览需接入 BSS 预估 API，最终费用以阿里云账单为准"}, "warnings": warnings})
}

func (s *Server) createTask(w http.ResponseWriter, r *http.Request, data map[string]any) {
	if !truthy(data["confirmed"]) {
		s.error(w, 400, "请先确认配置清单和费用提示")
		return
	}
	id := stringValue(data["previewId"])
	s.mu.Lock()
	payload, ok := s.previews[id]
	if ok {
		delete(s.previews, id)
	}
	s.mu.Unlock()
	if !ok {
		s.error(w, 400, "配置清单已过期，请重新预检")
		return
	}
	createdAt := int64(numberFloat(payload["_previewCreatedAt"]))
	if createdAt <= 0 || time.Now().Unix()-createdAt > 15*60 {
		s.error(w, 400, "配置清单已过期，请重新预检")
		return
	}
	delete(payload, "_previewCreatedAt")
	if stringValue(payload["loginPassword"]) == "" {
		payload["loginPassword"] = generatePassword()
		payload["loginUser"] = loginUser(stringValue(payload["osKey"]))
	}
	if err := s.Store.BlockCurrentlyStoppedInstances(); err != nil {
		s.error(w, 500, "无法锁定已有停机实例的自动开机状态")
		return
	}
	groupKey := stringValue(payload["accountGroupKey"])
	region := stringValue(payload["regionId"])
	instanceType := stringValue(payload["instanceType"])
	taskID := randomToken(16)
	if err := s.Store.CreateTask(taskID, id, groupKey, region, instanceType, payload); err != nil {
		s.error(w, 400, "任务创建失败")
		return
	}
	if err := s.Store.EnqueueJob(taskID, "create_ecs", taskID, payload); err != nil {
		s.error(w, 500, "任务入队失败")
		return
	}
	s.json(w, 202, map[string]any{"success": true, "queued": true, "taskId": taskID, "data": map[string]any{"task_id": taskID, "status": "queued"}})
}

func (s *Server) diskOptions(w http.ResponseWriter, r *http.Request, data map[string]any) {
	groupKey := stringValue(data["accountGroupKey"])
	groups, _ := s.Store.LoadGroups()
	var group *app.AccountGroup
	for i := range groups {
		if groups[i].GroupKey == groupKey {
			group = &groups[i]
			break
		}
	}
	if group == nil {
		s.error(w, 400, "账号组不存在")
		return
	}
	regionID := stringValue(data["regionId"])
	if regionID == "" {
		regionID = group.RegionID
	}
	instanceType := stringValue(data["instanceType"])
	if instanceType == "" {
		instanceType = "ecs.e-c4m1.large"
	}
	client := s.Cloud
	if s.CloudFactory != nil {
		client = s.CloudFactory(app.Account{AccessKeyID: group.AccessKeyID, AccessKeySecret: group.AccessKeySecret, RegionID: group.RegionID, SiteType: group.SiteType})
	}
	if client == nil {
		s.json(w, 200, map[string]any{"success": true, "data": map[string]any{"options": []map[string]any{{"value": "cloud_essd_entry", "label": "ESSD Entry", "min": 20, "max": 32768, "unit": "GB"}, {"value": "cloud_essd", "label": "ESSD", "min": 20, "max": 32768, "unit": "GB"}}, "regionId": regionID, "zoneId": ""}})
		return
	}
	preflight, ok := client.(cloud.PreflightClient)
	if !ok {
		s.error(w, 503, "当前云客户端不支持系统盘预检")
		return
	}
	zones, err := preflight.DescribeAvailableZones(r.Context(), regionID, instanceType, stringValue(data["systemDiskCategory"]))
	if err != nil || len(zones) == 0 {
		if err == nil {
			err = fmt.Errorf("没有可用区库存")
		}
		s.error(w, 400, "可用区预检失败: "+err.Error())
		return
	}
	zoneID := stringValue(data["zoneId"])
	if zoneID == "" {
		zoneID = firstMapString(zones, "ZoneId", "zoneId")
	}
	options, err := preflight.GetSystemDiskOptions(r.Context(), regionID, zoneID, instanceType)
	if err != nil {
		s.error(w, 400, "系统盘预检失败: "+err.Error())
		return
	}
	s.json(w, 200, map[string]any{"success": true, "data": map[string]any{"options": options, "regionId": regionID, "zoneId": zoneID, "instanceType": instanceType}})
}
func (s *Server) task(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("taskId")
	task, err := s.Store.GetTask(taskID)
	if errors.Is(err, os.ErrNotExist) || err != nil {
		s.error(w, 404, "任务不存在")
		return
	}
	s.json(w, 200, map[string]any{"success": true, "data": taskResponse(task)})
}

// taskResponse keeps the legacy snake_case API while also exposing the
// camelCase fields used by the existing Vue client during result display.
func taskResponse(task *app.EcsTask) map[string]any {
	return map[string]any{
		"task_id": task.TaskID, "taskId": task.TaskID,
		"preview_id": task.PreviewID, "previewId": task.PreviewID,
		"account_group_key": task.GroupKey, "accountGroupKey": task.GroupKey,
		"region_id": task.RegionID, "regionId": task.RegionID,
		"instance_type": task.InstanceType, "instanceType": task.InstanceType,
		"status": task.Status, "step": task.Step,
		"error_message": task.ErrorMessage, "errorMessage": task.ErrorMessage,
		"instance_id": task.InstanceID, "instanceId": task.InstanceID,
		"public_ip": task.PublicIP, "publicIp": task.PublicIP,
		"login_user": task.LoginUser, "loginUser": task.LoginUser,
		"login_password": task.LoginPassword, "loginPassword": task.LoginPassword,
		"payload": task.Payload, "created_at": task.CreatedAt, "updated_at": task.UpdatedAt,
	}
}

func (s *Server) control(w http.ResponseWriter, data map[string]any) {
	id := int64(number(data["accountId"], 0))
	a, err := s.Store.Account(id, false)
	if err != nil {
		s.error(w, 404, "账号不存在")
		return
	}
	action := stringValue(data["action"])
	if action != "start" && action != "stop" {
		s.error(w, 400, "无效的操作类型")
		return
	}
	client := s.Cloud
	if s.CloudFactory != nil {
		client = s.CloudFactory(*a)
	}
	if client == nil {
		s.cloudUnavailable(w)
		return
	}
	if action == "start" {
		err = client.StartInstance(rctx(), a.RegionID, a.InstanceID)
	} else {
		err = client.StopInstance(rctx(), a.RegionID, a.InstanceID, stringOrMap(data, "shutdownMode", "KeepCharging"))
	}
	if err != nil {
		s.error(w, 400, err.Error())
		return
	}
	newStatus := map[bool]string{true: "Starting", false: "Stopping"}[action == "start"]
	_ = s.Store.UpdateAccountStatus(id, a.TrafficUsed, newStatus, time.Now().Unix(), nil)
	if err := s.Store.SetAutoStartBlocked(id, action == "stop"); err != nil {
		s.error(w, 500, "实例状态已提交，但自动开机状态保存失败: "+err.Error())
		return
	}
	// A manual action starts a new operator-controlled state window. It must
	// clear any previous scheduled-stop block so manual start can take effect.
	if err := s.Store.SetScheduleStopActive(id, false); err != nil {
		s.error(w, 500, "实例状态已提交，但定时停机状态保存失败: "+err.Error())
		return
	}
	s.dispatchEvent(rctx(), notify.Event{Title: "实例控制指令已提交", Summary: fmt.Sprintf("%s 已提交%s指令", accountDisplay(*a), map[string]string{"start": "开机", "stop": "停机"}[action]), AccountID: accountDisplay(*a), Text: fmt.Sprintf("【ECS Controller】实例控制指令已提交\n实例: %s\n实例 ID: %s\n区域: %s\n动作: %s\n时间: %s", accountDisplay(*a), a.InstanceID, a.RegionID, action, time.Now().Format("2006-01-02 15:04:05")), Fields: map[string]string{"instance_id": a.InstanceID, "action": action, "region": a.RegionID}})
	s.json(w, 200, map[string]any{"success": true})
}
func (s *Server) deleteInstance(w http.ResponseWriter, data map[string]any) {
	id := int64(number(data["accountId"], 0))
	a, err := s.Store.Account(id, false)
	if err != nil {
		s.error(w, 404, "账号不存在")
		return
	}
	if s.Cloud == nil && s.CloudFactory == nil {
		s.cloudUnavailable(w)
		return
	}
	if a.InstanceStatus == "Releasing" {
		s.json(w, 202, map[string]any{"success": true, "queued": true})
		return
	}
	if err = s.Store.MarkReleasing(id); err != nil {
		s.error(w, 500, "无法锁定释放任务")
		return
	}
	jobID := randomToken(16)
	if err = s.Store.EnqueueJob(jobID, "delete_instance", strconv.FormatInt(id, 10), map[string]any{"accountId": id, "forceStop": truthy(data["forceStop"])}); err != nil {
		_ = s.Store.SetInstanceStatus(id, a.InstanceStatus)
		s.error(w, 500, "释放任务入队失败")
		return
	}
	s.dispatchEvent(rctx(), notify.Event{Title: "实例释放已提交", Summary: "实例已进入后台释放队列。", AccountID: accountDisplay(*a), Text: fmt.Sprintf("【ECS Controller】实例释放已提交\n实例: %s\n实例 ID: %s\n区域: %s\n后台队列会继续处理 ECS、EIP 和 DDNS 清理。", accountDisplay(*a), a.InstanceID, a.RegionID), Fields: map[string]string{"instance_id": a.InstanceID, "region": a.RegionID, "action": "release"}})
	s.json(w, 202, map[string]any{"success": true, "queued": true, "jobId": jobID})
}
func (s *Server) replaceIP(w http.ResponseWriter, data map[string]any) {
	id := int64(number(data["accountId"], 0))
	a, err := s.Store.Account(id, false)
	if err != nil {
		s.error(w, 404, "账号不存在")
		return
	}
	client := s.Cloud
	if s.CloudFactory != nil {
		client = s.CloudFactory(*a)
	}
	if client == nil {
		s.cloudUnavailable(w)
		return
	}
	if a.PublicIPMode != "eip" || !a.EIPManaged || a.EIPAllocationID == "" {
		s.error(w, 400, "当前实例不是系统托管 EIP，无法更换公网 IP")
		return
	}
	oldAllocationID, oldIP := a.EIPAllocationID, a.PublicIP
	alloc, ip, err := allocateEIP(rctx(), client, a.RegionID, a.InternetBandwidth)
	if err != nil {
		s.error(w, 400, err.Error())
		return
	}
	if err = client.UnassociateEIP(rctx(), a.RegionID, oldAllocationID); err != nil && !cloud.IsNotFound(err) {
		_ = client.ReleaseEIP(rctx(), a.RegionID, alloc)
		s.error(w, 400, "旧 EIP 解绑失败: "+err.Error())
		return
	}
	if err = client.AssociateEIP(rctx(), a.RegionID, alloc, a.InstanceID); err != nil {
		// Restore the old association when possible, then release the unused replacement.
		_ = client.AssociateEIP(rctx(), a.RegionID, oldAllocationID, a.InstanceID)
		_ = client.ReleaseEIP(rctx(), a.RegionID, alloc)
		s.error(w, 400, "新 EIP 绑定失败: "+err.Error())
		return
	}
	if err = client.ReleaseEIP(rctx(), a.RegionID, oldAllocationID); err != nil && !cloud.IsNotFound(err) {
		s.Store.AddLog("warning", "旧 EIP 释放失败: "+err.Error())
	}
	if err := s.Store.UpdateNetwork(id, map[string]any{"eip_allocation_id": alloc, "eip_address": ip, "public_ip": ip, "public_ip_mode": "eip", "eip_managed": true}); err != nil {
		s.error(w, 500, "新 EIP 已绑定，但本地状态保存失败: "+err.Error())
		return
	}
	s.dispatchEvent(rctx(), notify.Event{Title: "公网 IP 已更换", Summary: fmt.Sprintf("%s 的公网 IP 已更换", accountDisplay(*a)), AccountID: accountDisplay(*a), Text: fmt.Sprintf("【ECS Controller】公网 IP 已更换\n实例: %s\n旧 IP: %s\n新 IP: %s\n区域: %s", accountDisplay(*a), oldIP, ip, a.RegionID), Fields: map[string]string{"old_ip": oldIP, "new_ip": ip, "instance_id": a.InstanceID}})
	s.json(w, 200, map[string]any{"success": true, "message": "公网 IP 已更换", "data": map[string]any{"publicIp": ip, "publicIpMode": "eip", "eipAllocationId": alloc, "eipAddress": ip, "internetMaxBandwidthOut": a.InternetBandwidth}})
}

func allocateEIP(ctx context.Context, client cloud.Client, region string, bandwidth int) (string, string, error) {
	if bandwidthClient, ok := client.(cloud.BandwidthEIPClient); ok {
		return bandwidthClient.AllocateEIPWithBandwidth(ctx, region, bandwidth)
	}
	return client.AllocateEIP(ctx, region)
}

func (s *Server) refreshAccount(w http.ResponseWriter, data map[string]any) {
	id := int64(number(data["id"], number(data["accountId"], 0)))
	a, err := s.Store.Account(id, false)
	if err != nil {
		s.error(w, 404, "账号不存在")
		return
	}
	client := s.Cloud
	if s.CloudFactory != nil {
		client = s.CloudFactory(*a)
	}
	if client == nil {
		s.cloudUnavailable(w)
		return
	}
	instance, err := client.DescribeInstance(rctx(), a.RegionID, a.InstanceID)
	if err != nil {
		s.error(w, 400, err.Error())
		return
	}
	a.InstanceStatus, a.PublicIP, a.PrivateIP, a.InstanceType = instance.Status, instance.PublicIP, instance.PrivateIP, instance.InstanceType
	a.CPU, a.Memory, a.OSName = instance.CPU, instance.Memory, instance.OSName
	if a.PublicIPMode == "eip" && a.EIPAddress != "" {
		a.PublicIP = a.EIPAddress
	}
	now := time.Now()
	month := now.Format("2006-01")
	endMS := now.UnixMilli()
	monthlyTraffic := false
	if monthlyClient, ok := client.(cloud.MonthlyTrafficClient); ok {
		monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).UnixMilli()
		if bytes, points, monthlyErr := monthlyClient.GetInstanceMonthlyTraffic(rctx(), a.RegionID, a.InstanceID, a.PublicIP, monthStart, endMS); monthlyErr == nil && points > 0 {
			a.TrafficUsed = bytes / (1024 * 1024 * 1024)
			a.TrafficAPIStatus = "ok"
			a.TrafficAPIMessage = ""
			a.ProtectionSuspended = false
			a.ProtectionSuspendReason = ""
			monthlyTraffic = true
		}
	}
	if !monthlyTraffic {
		sample, sampleErr := s.Store.InstanceTrafficUsage(a.ID, a.InstanceID, month)
		if sampleErr != nil {
			s.error(w, 500, "流量账本读取失败")
			return
		}
		startMS := sample.LastSampleMS
		if startMS <= 0 || startMS >= endMS {
			startMS = endMS - int64(10*time.Minute/time.Millisecond)
		}
		traffic, _, _, _, metricErr := client.GetOutboundTrafficDelta(rctx(), a.RegionID, a.InstanceID, a.PublicIP, startMS, endMS)
		if metricErr == nil {
			if _, err := s.Store.AddInstanceTraffic(a.ID, a.InstanceID, month, traffic, endMS); err != nil {
				s.error(w, 500, "流量账本保存失败")
				return
			}
			updated, _ := s.Store.InstanceTrafficUsage(a.ID, a.InstanceID, month)
			a.TrafficUsed = updated.TrafficBytes / (1024 * 1024 * 1024)
			a.TrafficAPIStatus = "ok"
			a.TrafficAPIMessage = ""
			a.ProtectionSuspended = false
			a.ProtectionSuspendReason = ""
		} else if fallbackTraffic, fallbackErr := client.GetTraffic(rctx(), a.RegionID); fallbackErr == nil {
			a.TrafficUsed = fallbackTraffic
			a.TrafficAPIStatus = "fallback_cdt"
			a.TrafficAPIMessage = "CMS 月度实例指标不可用，已使用 CDT 聚合流量"
		} else {
			a.TrafficAPIStatus = "error"
			a.TrafficAPIMessage = metricErr.Error()
			a.ProtectionSuspended = true
			a.ProtectionSuspendReason = "traffic_api_error"
		}
	}
	_ = s.Store.AddTrafficHistory(a.ID, a.TrafficUsed, now)
	var billingErr error
	if s.Store.GetSetting("enable_billing", "0") == "1" {
		if billingClient, ok := client.(cloud.BillingClient); ok {
			if _, cacheOK := s.Store.GetBillingCache(a.ID, "balance", "", 6*time.Hour); !cacheOK {
				if balance, currency, err := billingClient.GetAccountBalance(rctx(), a.SiteType); err == nil {
					_ = s.Store.SetBillingCache(a.ID, "balance", "", map[string]any{"balance": balance, "currency": currency})
				} else {
					billingErr = err
					_ = s.Store.SetBillingCache(a.ID, "balance", "", map[string]any{"error": err.Error()})
				}
			}
			if _, cacheOK := s.Store.GetBillingCache(a.ID, "bill_overview", month, 6*time.Hour); !cacheOK {
				if total, currency, err := billingClient.GetBillOverview(rctx(), a.SiteType, month); err == nil {
					_ = s.Store.SetBillingCache(a.ID, "bill_overview", month, map[string]any{"monthly_cost": total, "currency": currency})
				} else {
					billingErr = err
					_ = s.Store.SetBillingCache(a.ID, "bill_overview", month, map[string]any{"error": err.Error()})
				}
			}
		}
		if _, ok := s.Store.GetBillingCache(a.ID, "instance_bill", month, 6*time.Hour); !ok {
			balance, cost, currency, err := client.GetBilling(rctx(), a.SiteType, a.InstanceID, month)
			if err != nil {
				billingErr = err
				_ = s.Store.SetBillingCache(a.ID, "instance_bill", month, map[string]any{"error": err.Error()})
			} else {
				_ = s.Store.SetBillingCache(a.ID, "instance_bill", month, map[string]any{"balance": balance, "monthly_cost": cost, "currency": currency})
			}
		}
	}
	a.UpdatedAt = now.Unix()
	a.HealthStatus = "ok"
	if err := s.Store.UpsertAccount(*a); err != nil {
		s.error(w, 500, "账号状态保存失败")
		return
	}
	response := map[string]any{"success": true, "traffic_status": a.TrafficAPIStatus, "traffic_message": a.TrafficAPIMessage}
	if billingErr != nil {
		response["billing_error"] = "账单查询失败: " + billingErr.Error()
	}
	s.json(w, 200, response)
}

func (s *Server) syncGroupAction(w http.ResponseWriter, data map[string]any) {
	count, err := s.syncGroup(stringValue(data["groupKey"]))
	if err != nil {
		s.error(w, 400, err.Error())
		return
	}
	s.json(w, 200, map[string]any{"success": true, "count": count})
}

func (s *Server) syncGroup(groupKey string) (int, error) {
	groups, err := s.Store.LoadGroups()
	if err != nil {
		return 0, err
	}
	var group *app.AccountGroup
	for i := range groups {
		if groups[i].GroupKey == groupKey {
			group = &groups[i]
			break
		}
	}
	if group == nil {
		return 0, fmt.Errorf("账号组不存在")
	}
	client := s.Cloud
	if s.CloudFactory != nil {
		client = s.CloudFactory(app.Account{AccessKeyID: group.AccessKeyID, AccessKeySecret: group.AccessKeySecret, RegionID: group.RegionID, SiteType: group.SiteType})
	}
	if client == nil {
		return 0, fmt.Errorf("云客户端未配置")
	}
	instances, err := client.DescribeInstances(rctx(), group.RegionID)
	if err != nil {
		return 0, err
	}
	accounts, err := s.Store.LoadAccounts(true)
	if err != nil {
		return 0, err
	}
	remoteIDs := make(map[string]bool, len(instances))
	count := 0
	for _, instance := range instances {
		remoteIDs[instance.ID] = true
		count++
		var existing *app.Account
		for i := range accounts {
			sameGroup := accounts[i].GroupKey == group.GroupKey || (accounts[i].AccessKeyID == group.AccessKeyID && accounts[i].RegionID == group.RegionID)
			if sameGroup && accounts[i].InstanceID == instance.ID {
				existing = &accounts[i]
				break
			}
		}
		if existing != nil && (existing.IsDeleted != 0 || existing.InstanceStatus == "Releasing") {
			// A user-triggered release must not be resurrected by a manual sync
			// while the remote ECS record is still visible.
			continue
		}
		a := app.Account{AccessKeyID: group.AccessKeyID, AccessKeySecret: group.AccessKeySecret, RegionID: group.RegionID, InstanceID: instance.ID, MaxTraffic: group.MaxTraffic, ScheduleEnabled: group.ScheduleEnabled, ScheduleStartEnabled: group.ScheduleStartEnabled, ScheduleStopEnabled: group.ScheduleStopEnabled, StartTime: group.StartTime, StopTime: group.StopTime, Remark: group.Remark, SiteType: group.SiteType, GroupKey: group.GroupKey, InstanceName: instance.Name, InstanceType: instance.InstanceType, PublicIP: instance.PublicIP, PrivateIP: instance.PrivateIP, CPU: instance.CPU, Memory: instance.Memory, OSName: instance.OSName, InstanceStatus: instance.Status, HealthStatus: "ok", UpdatedAt: time.Now().Unix()}
		if existing != nil {
			// Keep local runtime state (traffic, schedules, protection flags and
			// managed-network metadata) while refreshing cloud-owned fields.
			a.ID = existing.ID
			a.TrafficUsed, a.TrafficBillingMonth = existing.TrafficUsed, existing.TrafficBillingMonth
			a.LastKeepAliveAt, a.AutoStartBlocked = existing.LastKeepAliveAt, existing.AutoStartBlocked
			a.ScheduleLastStartDate, a.ScheduleLastStopDate = existing.ScheduleLastStartDate, existing.ScheduleLastStopDate
			a.ScheduleStopActive, a.ScheduleBlockedByTraffic = existing.ScheduleStopActive, existing.ScheduleBlockedByTraffic
			a.TrafficAPIStatus, a.TrafficAPIMessage = existing.TrafficAPIStatus, existing.TrafficAPIMessage
			a.ProtectionSuspended, a.ProtectionSuspendReason, a.ProtectionNotifiedAt = existing.ProtectionSuspended, existing.ProtectionSuspendReason, existing.ProtectionNotifiedAt
			a.EIPAllocationID, a.EIPAddress, a.EIPManaged = existing.EIPAllocationID, existing.EIPAddress, existing.EIPManaged
			a.PublicIPMode = existing.PublicIPMode
			a.InternetBandwidth = existing.InternetBandwidth
			if a.PublicIPMode == "eip" && a.EIPAddress != "" {
				a.PublicIP = a.EIPAddress
			}
		}
		if err := s.Store.UpsertAccount(a); err != nil {
			return count, err
		}
	}
	for _, account := range accounts {
		if account.InstanceID == "" || account.IsDeleted != 0 || remoteIDs[account.InstanceID] {
			continue
		}
		sameGroup := account.GroupKey == group.GroupKey || (account.AccessKeyID == group.AccessKeyID && account.RegionID == group.RegionID)
		if !sameGroup {
			continue
		}
		// The instance disappeared outside this controller. Route it through
		// the same safe delete queue so EIP and DDNS cleanup still happens.
		if err := s.Store.MarkReleasing(account.ID); err != nil {
			return count, err
		}
		_ = s.Store.EnqueueJob(randomToken(16), "delete_instance", strconv.FormatInt(account.ID, 10), map[string]any{"accountId": account.ID, "forceStop": true})
	}
	if s.Store.GetSetting("ddns_enabled", "0") == "1" {
		_ = s.Store.SetSetting("last_ddns_reconcile", "0")
	}
	return count, nil
}

func (s *Server) fetchInstances(w http.ResponseWriter, data map[string]any) {
	accessKey, secret, region := stringValue(data["accessKeyId"]), stringValue(data["accessKeySecret"]), stringValue(data["regionId"])
	if accessKey == "" || secret == "" || region == "" {
		s.error(w, 400, "AK、Secret 和区域不能为空")
		return
	}
	instances, err := cloud.NewRPCService(accessKey, secret, region).DescribeInstances(rctx(), region)
	if err != nil {
		s.error(w, 400, err.Error())
		return
	}
	s.json(w, 200, map[string]any{"success": true, "data": instances})
}

func (s *Server) testAccount(w http.ResponseWriter, data map[string]any) {
	account, _ := data["account"].(map[string]any)
	if account == nil {
		s.error(w, 400, "账号数据不能为空")
		return
	}
	accessKey, secret, region := stringValue(account["AccessKeyId"]), stringValue(account["AccessKeySecret"]), stringValue(account["regionId"])
	if secret == "********" {
		var err error
		secret, err = s.resolveMaskedAccountSecret(account, accessKey, region)
		if err != nil {
			s.error(w, 400, err.Error())
			return
		}
	}
	if accessKey == "" || secret == "" || region == "" {
		s.error(w, 400, "AK、Secret 和区域不能为空")
		return
	}
	client := cloud.NewRPCService(accessKey, secret, region)
	regions, err := client.DescribeRegions(rctx())
	if err != nil {
		s.json(w, 200, map[string]any{"success": false, "message": err.Error()})
		return
	}
	regionFound := false
	for _, item := range regions {
		if firstMapString([]map[string]any{item}, "RegionId", "regionId") == region {
			regionFound = true
			break
		}
	}
	if !regionFound {
		s.json(w, 200, map[string]any{"success": false, "message": "当前 AK 无法访问所选区域"})
		return
	}
	instances, err := client.DescribeInstances(rctx(), region)
	if err != nil {
		s.json(w, 200, map[string]any{"success": false, "message": err.Error()})
		return
	}
	monitorStatus, monitorMessage := "skipped", "当前区域暂无实例，未执行云监控流量探测"
	if len(instances) > 0 {
		probe := instances[0]
		end := time.Now().Add(-90 * time.Second).Truncate(time.Minute).UnixMilli()
		_, _, _, _, metricErr := client.GetOutboundTrafficDelta(rctx(), region, probe.ID, probe.PublicIP, end-10*60*1000, end)
		if metricErr != nil {
			monitorStatus, monitorMessage = "warning", "云监控流量探测未通过: "+metricErr.Error()
		} else {
			monitorStatus, monitorMessage = "ok", "云监控接口已接通，可获取实例流量"
		}
	}
	maxTraffic := number(account["maxTraffic"], 0)
	usageUsed := numberFloat(account["usageUsed"])
	s.json(w, 200, map[string]any{"success": true, "message": "AK 可用，ECS API 已接通", "monitorStatus": monitorStatus, "monitorMessage": monitorMessage, "instanceCount": len(instances), "usageUsed": usageUsed, "usageRemaining": maxFloat(float64(maxTraffic)-usageUsed, 0), "usagePercent": mapPercent(usageUsed, float64(maxTraffic))})
}

func (s *Server) resolveMaskedAccountSecret(account map[string]any, accessKey, region string) (string, error) {
	groups, err := s.Store.LoadGroups()
	if err != nil {
		return "", fmt.Errorf("读取账号凭据失败: %w", err)
	}
	groupKey := stringValue(account["groupKey"])
	for _, group := range groups {
		if group.AccessKeyID != accessKey || group.RegionID != region {
			continue
		}
		if groupKey != "" && group.GroupKey != groupKey {
			continue
		}
		if group.AccessKeySecret != "" && group.AccessKeySecret != "********" {
			return group.AccessKeySecret, nil
		}
	}
	return "", fmt.Errorf("AK Secret 已被隐藏，请重新输入完整的 AK Secret")
}

func (s *Server) testNotification(w http.ResponseWriter, action string, data map[string]any) {
	ctx := rctx()
	var err error
	switch action {
	case "send_test_webhook":
		cfg, _ := data["webhook"].(map[string]any)
		headers := map[string]string{}
		if raw := stringValue(cfg["headers"]); raw != "" {
			_ = json.Unmarshal([]byte(raw), &headers)
		}
		err = notify.Webhook(ctx, stringValue(cfg["url"]), stringValue(cfg["method"]), stringValue(cfg["request_type"]), headers, map[string]any{"event": "test", "message": "ECS Controller test notification"})
	case "send_test_telegram":
		cfg, _ := data["telegram"].(map[string]any)
		token := stringValue(cfg["token"])
		if token == "********" {
			token, _ = s.Store.OpenSecret(s.Store.GetSetting("notify_tg_token", ""))
		}
		settings := s.Store.Settings()
		proxyType := fallback(stringValue(cfg["proxy_type"]), settings["notify_tg_proxy_type"])
		proxyURL := fallback(stringValue(cfg["proxy_url"]), settings["notify_tg_proxy_url"])
		proxyIP := fallback(stringValue(cfg["proxy_ip"]), settings["notify_tg_proxy_ip"])
		proxyPort := fallback(stringValue(cfg["proxy_port"]), settings["notify_tg_proxy_port"])
		proxyUser := fallback(stringValue(cfg["proxy_user"]), settings["notify_tg_proxy_user"])
		proxyPass, _ := s.Store.OpenSecret(settings["notify_tg_proxy_pass"])
		client, clientErr := notify.NewTelegramClient(token, proxyType, proxyURL, proxyIP, proxyPort, proxyUser, proxyPass)
		if clientErr != nil {
			err = clientErr
		} else {
			err = client.SendMessage(ctx, stringValue(cfg["chat_id"]), "ECS Controller 测试消息", nil)
		}
	case "send_test_email":
		settings := s.Store.Settings()
		password, _ := s.Store.OpenSecret(settings["notify_password"])
		to := stringValue(data["email"])
		if to == "" {
			to = settings["notify_email"]
		}
		err = notify.Email(ctx, settings["notify_host"], numberString(settings["notify_port"], 465), settings["notify_username"], password, settings["notify_username"], to, "ECS Controller 测试消息", "通知通道测试成功。", settings["notify_secure"])
	}
	if err != nil {
		s.json(w, 200, map[string]any{"success": false, "message": err.Error()})
		return
	}
	s.json(w, 200, map[string]any{"success": true, "message": "测试消息已发送"})
}

func (s *Server) uploadLogo(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		s.error(w, 400, "Logo 图片大小需小于 2MB")
		return
	}
	f, _, err := r.FormFile("logo")
	if err != nil {
		s.error(w, 400, "Logo 文件无效")
		return
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	typ := http.DetectContentType(buf[:n])
	ext := map[string]string{"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}[typ]
	if ext == "" {
		s.error(w, 400, "仅支持 PNG、JPG、WebP 图片")
		return
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		s.error(w, 500, "Logo 读取失败")
		return
	}
	for _, old := range []string{"png", "jpg", "webp"} {
		_ = os.Remove(filepath.Join(s.DataDir, "brand-logo."+old))
	}
	tmp, err := os.CreateTemp(s.DataDir, "brand-logo-*")
	if err != nil {
		s.error(w, 500, "Logo 存储目录不可写")
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = io.Copy(tmp, f); err != nil {
		tmp.Close()
		s.error(w, 500, "Logo 保存失败")
		return
	}
	tmp.Close()
	target := filepath.Join(s.DataDir, "brand-logo."+ext)
	if err = os.Rename(tmpName, target); err != nil {
		s.error(w, 500, "Logo 保存失败")
		return
	}
	_ = s.Store.SetSetting("app_logo_url", "index.php?action=brand_logo&v="+strconv.FormatInt(time.Now().Unix(), 10))
	s.json(w, 200, map[string]any{"success": true, "url": "index.php?action=brand_logo"})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if id := cookieID(r); id != "" {
		s.Store.DeleteSession(id)
	}
	http.SetCookie(w, &http.Cookie{Name: "ecs_session", MaxAge: -1, Path: "/"})
	s.json(w, 200, map[string]any{"success": true})
}
func (s *Server) authenticated(r *http.Request) bool { _, ok := s.session(r); return ok }
func (s *Server) session(r *http.Request) (string, bool) {
	c, err := r.Cookie("ecs_session")
	if err != nil {
		return "", false
	}
	return s.Store.Session(c.Value)
}
func (s *Server) createSession(w http.ResponseWriter) {
	id, csrf := randomToken(32), randomToken(24)
	_ = s.Store.CreateSession(id, csrf, 12*time.Hour)
	http.SetCookie(w, &http.Cookie{Name: "ecs_session", Value: id, Path: "/", HttpOnly: true, Secure: s.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 43200})
	w.Header().Set("X-CSRF-Token", csrf)
}
func (s *Server) csrfOK(w http.ResponseWriter, r *http.Request) bool {
	csrf, ok := s.session(r)
	if !ok || csrf == "" || r.Header.Get("X-CSRF-Token") != csrf {
		s.error(w, 403, "CSRF token 无效")
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" && !sameOriginHost(origin, r.Host) {
		s.error(w, 403, "请求来源不受信任")
		return false
	}
	return true
}
func (s *Server) mutating(a string) bool {
	switch a {
	case "save_config", "upload_logo", "clear_logs", "logout", "create_ecs", "control_instance", "delete_instance", "replace_instance_ip", "refresh_account", "sync_account_group", "restore_schedule_block", "send_test_email", "send_test_telegram", "send_test_webhook", "start_update":
		return true
	}
	return false
}
func (s *Server) json(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Server) error(w http.ResponseWriter, status int, message string) {
	s.json(w, status, map[string]any{"success": false, "error": message, "message": message})
}
func (s *Server) cloudUnavailable(w http.ResponseWriter) {
	s.error(w, 503, "云客户端未配置，请设置阿里云凭据后重试")
}

func (s *Server) dispatchEvent(ctx context.Context, event notify.Event) {
	cfg := notify.ConfigFromSettings(s.Store.Settings(), s.Store.OpenSecret)
	if err := (notify.Dispatcher{Config: cfg}).Dispatch(ctx, event); err != nil {
		s.Store.AddLog("warning", "通知发送失败: "+err.Error())
	}
}

func accountDisplay(account app.Account) string {
	if account.Remark != "" {
		return account.Remark
	}
	if account.InstanceName != "" {
		return account.InstanceName
	}
	if account.InstanceID != "" {
		return account.InstanceID
	}
	return account.AccessKeyID
}

func (s *Server) saveSecret(key, value string) error {
	if value == "" || value == "********" {
		return nil
	}
	sealed, err := s.Store.Seal(value)
	if err != nil {
		return err
	}
	return s.Store.SetSetting(key, sealed)
}
func masked(value string) string {
	if value == "" {
		return ""
	}
	return "********"
}
func notificationSettings(m map[string]string) map[string]any {
	return map[string]any{"email_enabled": settingBool(m["notify_email_enabled"], true), "email": m["notify_email"], "host": m["notify_host"], "port": numberString(m["notify_port"], 465), "username": m["notify_username"], "password": masked(m["notify_password"]), "secure": fallback(m["notify_secure"], "ssl"), "daily_enabled": settingBool(m["notify_daily_enabled"], false), "daily_time": fallback(m["notify_daily_time"], "00:00"), "telegram": map[string]any{"enabled": settingBool(m["notify_tg_enabled"], false), "token": masked(m["notify_tg_token"]), "chat_id": m["notify_tg_chat_id"], "proxy_type": fallback(m["notify_tg_proxy_type"], "none"), "proxy_url": m["notify_tg_proxy_url"], "proxy_ip": m["notify_tg_proxy_ip"], "proxy_port": m["notify_tg_proxy_port"], "proxy_user": m["notify_tg_proxy_user"], "proxy_pass": masked(m["notify_tg_proxy_pass"]), "allowed_user_ids": m["notify_tg_allowed_user_ids"], "confirm_ttl": numberString(m["notify_tg_confirm_ttl"], 60)}, "webhook": map[string]any{"enabled": settingBool(m["notify_wh_enabled"], false), "url": m["notify_wh_url"], "method": fallback(m["notify_wh_method"], "GET"), "request_type": fallback(m["notify_wh_request_type"], "JSON"), "headers": m["notify_wh_headers"], "body": m["notify_wh_body"]}}
}

// settingBool accepts both the current 0/1 representation and values written
// by older builds that persisted JavaScript booleans as "true"/"false".
func settingBool(value string, defaultValue bool) bool {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return truthy(value)
}
func readJSON(r *http.Request) (map[string]any, error) {
	if r.Body == nil {
		return map[string]any{}, nil
	}
	var data map[string]any
	err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("请求 JSON 无效")
	}
	if data == nil {
		data = map[string]any{}
	}
	return data, nil
}
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func generatePassword() string { return randomToken(12) + "Aa1!" }
func loginUser(osKey string) string {
	if strings.HasPrefix(strings.ToLower(osKey), "windows") {
		return "Administrator"
	}
	return "root"
}

func loginPortForOS(osKey string) int {
	if strings.HasPrefix(strings.ToLower(osKey), "windows") {
		return 3389
	}
	return 22
}

func normalizeArchitecture(value string) string {
	value = strings.ToLower(value)
	if strings.Contains(value, "arm") || strings.Contains(value, "aarch64") {
		return "arm64"
	}
	if strings.Contains(value, "x86") || strings.Contains(value, "amd64") || strings.Contains(value, "i386") {
		return "x86_64"
	}
	return ""
}

func firstMapString(items []map[string]any, keys ...string) string {
	for _, item := range items {
		for _, key := range keys {
			if value := stringValue(item[key]); value != "" && value != "<nil>" {
				return value
			}
		}
	}
	return ""
}

func containsMapValue(items []map[string]any, expected string, keys ...string) bool {
	for _, item := range items {
		for _, key := range keys {
			if stringValue(item[key]) == expected {
				return true
			}
		}
	}
	return false
}

func selectDiskOption(options []map[string]any, requested string) map[string]any {
	for _, option := range options {
		if stringValue(option["value"]) == requested {
			return option
		}
	}
	return options[0]
}

func osInfo(key string) (string, string) {
	switch key {
	case "ubuntu_22":
		return "Ubuntu 22.04 LTS", "ubuntu_22_04_x64_20G_alibase_20240108.vhd"
	case "ubuntu_24":
		return "Ubuntu 24.04 LTS", "ubuntu_24_04_x64_20G_alibase_20240528.vhd"
	case "alibaba_cloud_linux_3":
		return "Alibaba Cloud Linux 3", "aliyun_3_x64_20G_alibase_20240528.vhd"
	case "centos_stream_9":
		return "CentOS Stream 9", "centos_stream_9_x64_20G_alibase_20240219.vhd"
	case "windows_2022":
		return "Windows Server 2022", "win2022_21H2_x64_dtc_zh-cn_40G_alibase_20240119.vhd"
	default:
		return "Debian 12", "debian_12_0_x64_20G_alibase_20240228.vhd"
	}
}
func maskAccessKey(value string) string {
	if len(value) <= 7 {
		return value
	}
	return value[:7] + "***"
}
func cookieID(r *http.Request) string {
	c, err := r.Cookie("ecs_session")
	if err != nil {
		return ""
	}
	return c.Value
}
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func expectedOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func sameOriginHost(origin, requestHost string) bool {
	origin = strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	return strings.EqualFold(strings.TrimSuffix(origin, "/"), requestHost)
}
func number(v any, fallback int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		i, e := strconv.Atoi(n)
		if e == nil {
			return i
		}
	}
	return fallback
}
func maxInt(value, minimum int) int {
	if value < minimum {
		return minimum
	}
	return value
}
func numberString(v string, fallback int) int {
	if i, e := strconv.Atoi(v); e == nil {
		return i
	}
	return fallback
}
func numberFloat(v any) float64 {
	switch value := v.(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case string:
		parsed, _ := strconv.ParseFloat(value, 64)
		return parsed
	}
	return 0
}
func mapPercent(used, total float64) float64 {
	if total <= 0 {
		return 0
	}
	return used / total * 100
}
func maxFloat(value, floor float64) float64 {
	if value < floor {
		return floor
	}
	return value
}
func stringValue(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return fmt.Sprint(v)
}
func fallback(v, f string) string {
	if v == "" || v == "<nil>" {
		return f
	}
	return v
}
func bool01(v any) string {
	if truthy(v) {
		return "1"
	}
	return "0"
}
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x == "1" || strings.EqualFold(x, "true")
	}
	return false
}
func stringOrMap(m map[string]any, k, f string) string { v := stringValue(m[k]); return fallback(v, f) }
func rctx() context.Context                            { return context.Background() }
