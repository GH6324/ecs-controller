package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

func TestServicePreflightAndEIPRequestSemantics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.URL.Query().Get("Action")
		var response any
		switch action {
		case "DescribeInstanceTypes":
			response = map[string]any{"InstanceTypes": map[string]any{"InstanceType": []any{map[string]any{"InstanceTypeId": "ecs.test", "CpuArchitecture": "X86"}}}}
		case "DescribeAvailableResource":
			if r.URL.Query().Get("DestinationResource") == "SystemDisk" {
				response = map[string]any{"AvailableResources": map[string]any{"AvailableResource": []any{map[string]any{"Value": "cloud_essd", "MinSystemDiskSize": 40, "MaxSystemDiskSize": 200}}}}
			} else {
				response = map[string]any{"AvailableZones": map[string]any{"AvailableZone": []any{map[string]any{"ZoneId": "zone-a", "Status": "Available"}}}}
			}
		case "DescribeImages":
			response = map[string]any{"Images": map[string]any{"Image": []any{map[string]any{"ImageId": "img-1", "OSName": "Ubuntu 22.04", "Architecture": "x86_64"}}}}
		case "RunInstances":
			if r.URL.Query().Get("AllocatePublicIp") != "false" || r.URL.Query().Get("InternetMaxBandwidthOut") != "0" || r.URL.Query().Get("ClientToken") != "task-1" {
				t.Fatalf("unexpected RunInstances parameters: %v", r.URL.Query())
			}
			response = map[string]any{"InstanceId": "i-1"}
		case "AllocateEipAddress":
			if r.URL.Query().Get("Bandwidth") != "20" {
				t.Fatalf("unexpected EIP bandwidth: %v", r.URL.Query())
			}
			response = map[string]any{"AllocationId": "eip-1", "EipAddress": "203.0.113.10"}
		default:
			response = map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &RPCClient{HTTPClient: server.Client(), Endpoint: server.URL, Version: "2014-05-26", Product: "Ecs", AccessKey: "ak", Secret: "sk"}
	service := &Service{ECS: client, EIP: client}
	typeInfo, err := service.DescribeInstanceType(context.Background(), "cn-test", "ecs.test")
	if err != nil || typeInfo["CpuArchitecture"] != "X86" {
		t.Fatalf("instance type: %#v %v", typeInfo, err)
	}
	zones, err := service.DescribeAvailableZones(context.Background(), "cn-test", "ecs.test", "cloud_essd")
	if err != nil || len(zones) != 1 || zones[0]["ZoneId"] != "zone-a" {
		t.Fatalf("zones: %#v %v", zones, err)
	}
	images, err := service.DescribeImagesForArchitecture(context.Background(), "cn-test", "ubuntu_22", "x86_64")
	if err != nil || len(images) != 1 {
		t.Fatalf("images: %#v %v", images, err)
	}
	disks, err := service.GetSystemDiskOptions(context.Background(), "cn-test", "zone-a", "ecs.test")
	if err != nil || len(disks) != 1 || disks[0]["min"] != 40 {
		t.Fatalf("disks: %#v %v", disks, err)
	}
	result, err := service.RunInstances(context.Background(), RunRequest{RegionID: "cn-test", ZoneID: "zone-a", InstanceType: "ecs.test", ImageID: "img-1", InstanceName: "test", SecurityGroupID: "sg-1", VSwitchID: "vs-1", Bandwidth: 20, PublicIPMode: "eip", Password: "Password123!", ClientToken: "task-1"})
	if err != nil || result.InstanceID != "i-1" {
		t.Fatalf("run result: %#v %v", result, err)
	}
	allocationID, ip, err := service.AllocateEIPWithBandwidth(context.Background(), "cn-test", 20)
	if err != nil || allocationID != "eip-1" || ip != "203.0.113.10" {
		t.Fatalf("allocate EIP result: %q %q %v", allocationID, ip, err)
	}
}

func TestDescribeInstancesPaginatesAndRejectsIncompletePages(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		page := r.URL.Query().Get("PageNumber")
		if r.URL.Query().Get("PageSize") != "100" {
			t.Fatalf("unexpected page size: %s", r.URL.Query().Get("PageSize"))
		}
		items := make([]map[string]any, 0)
		if page == "1" {
			for i := 0; i < 100; i++ {
				items = append(items, map[string]any{"InstanceId": fmt.Sprintf("i-%d", i), "Status": "Running"})
			}
		} else if page == "2" {
			items = append(items, map[string]any{"InstanceId": "i-100", "Status": "Stopped"})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"TotalCount": 101, "Instances": map[string]any{"Instance": items}})
	}))
	defer server.Close()

	service := &Service{ECS: &RPCClient{HTTPClient: server.Client(), Endpoint: server.URL, Version: "2014-05-26", Product: "Ecs", AccessKey: "ak", Secret: "sk"}}
	instances, err := service.DescribeInstances(context.Background(), "cn-test")
	if err != nil || len(instances) != 101 || calls != 2 || instances[100].ID != "i-100" {
		t.Fatalf("pagination result: count=%d calls=%d err=%v", len(instances), calls, err)
	}

	emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"TotalCount":1,"Instances":{"Instance":[]}}`))
	}))
	defer emptyServer.Close()
	emptyService := &Service{ECS: &RPCClient{HTTPClient: emptyServer.Client(), Endpoint: emptyServer.URL, Version: "2014-05-26", Product: "Ecs", AccessKey: "ak", Secret: "sk"}}
	if _, err := emptyService.DescribeInstances(context.Background(), "cn-test"); err == nil {
		t.Fatal("incomplete instance page was accepted")
	}
}

func TestDiskOptionsResponseNestedSupportedResources(t *testing.T) {
	root := map[string]any{"AvailableZones": map[string]any{"AvailableZone": []any{map[string]any{"AvailableResources": map[string]any{"AvailableResource": []any{map[string]any{"SupportedResources": map[string]any{"SupportedResource": []any{map[string]any{"Value": "cloud_efficiency"}}}}}}}}}}
	options := diskOptionsFromResponse(root)
	if len(options) != 1 || options[0]["value"] != "cloud_efficiency" {
		t.Fatalf("options: %#v", options)
	}
}

func TestOutboundTrafficUsesCMSDimensionObject(t *testing.T) {
	var dimensions []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dimensions = append(dimensions, r.URL.Query().Get("Dimensions"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Code":"200","Datapoints":"[]"}`))
	}))
	defer server.Close()

	service := &Service{CMS: &RPCClient{HTTPClient: server.Client(), Endpoint: server.URL, Version: "2019-01-01", Product: "Cms", AccessKey: "ak", Secret: "sk"}}
	_, _, _, _, err := service.GetOutboundTrafficDelta(context.Background(), "cn-hongkong", "i-1", "203.0.113.10", 1000, 2000)
	if err == nil {
		t.Fatal("empty CMS datapoints were accepted as a zero-traffic sample")
	}
	if len(dimensions) != 2 || dimensions[0] != `{"instanceId":"i-1","ip":"203.0.113.10"}` || dimensions[1] != `{"instanceId":"i-1"}` {
		t.Fatalf("unexpected CMS dimensions: %#v", dimensions)
	}
}

func TestMonthlyTrafficUsesHourlyCMSData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("Period") != "3600" {
			t.Fatalf("monthly query used the wrong period: %s", r.URL.Query().Get("Period"))
		}
		if r.URL.Query().Get("StartTime") != "1000" || r.URL.Query().Get("EndTime") != "5000" {
			t.Fatalf("monthly query used the wrong range: %s - %s", r.URL.Query().Get("StartTime"), r.URL.Query().Get("EndTime"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Code":"200","Datapoints":"[{\"timestamp\":2000,\"Average\":8}]"}`))
	}))
	defer server.Close()

	service := &Service{CMS: &RPCClient{HTTPClient: server.Client(), Endpoint: server.URL, Version: "2019-01-01", Product: "Cms", AccessKey: "ak", Secret: "sk"}}
	bytes, points, err := service.GetInstanceMonthlyTraffic(context.Background(), "cn-hongkong", "i-1", "203.0.113.10", 1000, 5000)
	if err != nil || points != 1 || bytes != 3600 {
		t.Fatalf("monthly traffic: bytes=%v points=%d err=%v", bytes, points, err)
	}
}

func TestDailyTrafficUsesExactCalendarWindow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("Period") != "3600" {
			t.Fatalf("daily query used the wrong period: %s", r.URL.Query().Get("Period"))
		}
		if r.URL.Query().Get("Length") != "48" {
			t.Fatalf("daily query used the wrong length: %s", r.URL.Query().Get("Length"))
		}
		if r.URL.Query().Get("StartTime") != "1753920000000" || r.URL.Query().Get("EndTime") != "1754006400000" {
			t.Fatalf("daily query used the wrong range: %s - %s", r.URL.Query().Get("StartTime"), r.URL.Query().Get("EndTime"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"Code\":\"200\",\"Datapoints\":\"[{\\\"timestamp\\\":1753923600000,\\\"Average\\\":8}]\"}"))
	}))
	defer server.Close()

	service := &Service{CMS: &RPCClient{HTTPClient: server.Client(), Endpoint: server.URL, Version: "2019-01-01", Product: "Cms", AccessKey: "ak", Secret: "sk"}}
	bytes, points, err := service.GetInstanceDailyTraffic(context.Background(), "cn-hongkong", "i-1", "203.0.113.10", 1753920000000, 1754006400000)
	if err != nil || points != 1 || bytes != 3600 {
		t.Fatalf("daily traffic: bytes=%v points=%d err=%v", bytes, points, err)
	}
}

func TestInstanceFromMapSupportsCurrentECSFieldsAndNestedIPs(t *testing.T) {
	instance := instanceFromMap(map[string]any{
		"InstanceId":     "i-1",
		"InstanceName":   "demo",
		"Status":         "Running",
		"InstanceTypeId": "ecs.test",
		"CpuCoreCount":   "4",
		"MemorySizeInMB": "8192",
		"OSNameEn":       "Ubuntu 22.04",
		"EipAddress":     map[string]any{"IpAddress": []any{"203.0.113.10"}},
		"VpcAttributes":  map[string]any{"PrivateIpAddress": map[string]any{"IpAddress": []any{"172.16.0.10"}}},
	})
	if instance.InstanceType != "ecs.test" || instance.CPU != 4 || instance.Memory != 8192 || instance.OSName != "Ubuntu 22.04" {
		t.Fatalf("instance hardware fields were not parsed: %#v", instance)
	}
	if instance.PublicIP != "203.0.113.10" || instance.PrivateIP != "172.16.0.10" {
		t.Fatalf("nested IP fields were not parsed: %#v", instance)
	}
}

func TestHongKongCountsAsOverseasCDTRegion(t *testing.T) {
	if !overseasRegion("cn-hongkong") || overseasRegion("cn-shanghai") || !overseasRegion("ap-southeast-1") {
		t.Fatal("CDT region classification is incorrect")
	}
}

func TestGetBillingDetailsUsesDailySplitItemBill(t *testing.T) {
	var mu sync.Mutex
	requests := make([]url.Values, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.Query())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{
			"Code": "Success",
			"Data": map[string]any{
				"Items": []map[string]any{{
					"BillingDate":      "2026-08-01",
					"ProductName":      "云服务器 ECS",
					"ProductCode":      "ecs",
					"ProductDetail":    "按量付费 ECS 计算资源",
					"BillingItem":      "计算资源",
					"BillingItemCode":  "instance",
					"BillingType":      "按量付费",
					"SubscriptionType": "PayAsYouGo",
					"PretaxAmount":     "1.25",
					"Currency":         "CNY",
					"InstanceID":       "i-1",
					"InstanceSpec":     "ecs.test",
					"ServicePeriod":    "86400",
				}},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	service := &Service{BSS: &RPCClient{
		Endpoint:   server.URL,
		Version:    "2017-12-14",
		Product:    "BssOpenApi",
		AccessKey:  "ak",
		Secret:     "secret",
		HTTPClient: server.Client(),
	}}
	details, err := service.GetBillingDetails(context.Background(), "china", "2026-08", "2026-08-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(details) != 1 || details[0].Date != "2026-08-01" || details[0].Amount != 1.25 || details[0].BillingItem != "计算资源" || details[0].ProductDetail != "按量付费 ECS 计算资源" {
		t.Fatalf("unexpected billing details: %#v", details)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 1 {
		t.Fatalf("billing API calls=%d, want 1", len(requests))
	}
	if got := requests[0].Get("Action"); got != "DescribeSplitItemBill" {
		t.Fatalf("action=%q, want DescribeSplitItemBill", got)
	}
	if got := requests[0].Get("Granularity"); got != "DAILY" {
		t.Fatalf("granularity=%q, want DAILY", got)
	}
	if got := requests[0].Get("BillingCycle"); got != "2026-08" {
		t.Fatalf("billing cycle=%q", got)
	}
	if got := requests[0].Get("BillingDate"); got != "2026-08-01" {
		t.Fatalf("billing date=%q", got)
	}
	if got := requests[0].Get("IsHideZeroCharge"); got != "true" {
		t.Fatalf("hide zero charge=%q", got)
	}
}
