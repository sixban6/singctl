package netdiag

import (
	"testing"
)

func TestInspectHop(t *testing.T) {
	tests := []struct {
		ip          string
		host        string
		wantTag     string
		wantCarrier string
		wantRoute   string
		wantASN     string
	}{
		{"59.43.18.1", "", "CN2 (59.43)", "中国电信", "CN2", "AS4809"},
		{"202.97.22.1", "", "163 (202.97)", "中国电信", "163", "AS4134"},
		{"218.105.10.1", "", "9929 (CU-Premium)", "中国联通", "9929", "AS9929"},
		{"210.51.10.1", "", "9929 (CU-Premium)", "中国联通", "9929", "AS9929"},
		{"219.158.113.1", "", "4837 (CU-169)", "中国联通", "4837", "AS4837"},
		{"223.120.22.1", "", "CMIN2 (223.120)", "中国移动", "CMIN2", "AS58807"},
		{"221.183.55.1", "", "CMI (AS9808)", "中国移动", "CMI", "AS9808"},
		{"183.91.1.1", "", "CMI (AS9808)", "中国移动", "CMI", "AS9808"},
		{"129.250.0.1", "ae-0.gin.ntt.net", "NTT", "国际中转", "NTT", "AS2914"},
		{"154.54.0.1", "be210.ccr41.lax05.atlas.cogentco.com", "Cogent", "国际中转", "Cogent", "AS174"},
		{"210.130.0.1", "iij.net", "IIJ", "日本直连", "IIJ", "AS2497"},
	}

	for _, tt := range tests {
		tag, carrier, route, asn := InspectHop(tt.ip, tt.host)
		if tag != tt.wantTag || carrier != tt.wantCarrier || route != tt.wantRoute || asn != tt.wantASN {
			t.Errorf("InspectHop(%q, %q) = (%q, %q, %q, %q), want (%q, %q, %q, %q)",
				tt.ip, tt.host, tag, carrier, route, asn, tt.wantTag, tt.wantCarrier, tt.wantRoute, tt.wantASN)
		}
	}
}

func TestClassifyRoute(t *testing.T) {
	// 1. Pure CN2 GIA (59.43 only, no 202.97)
	giaHops := []HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "59.43.18.1"},
		{Hop: 3, IP: "59.43.247.1"},
		{Hop: 4, IP: "154.22.1.1"},
	}
	name, rType, _ := ClassifyRoute(giaHops)
	if rType != "CN2_GIA" {
		t.Errorf("expected CN2_GIA, got %s (%s)", rType, name)
	}

	// 2. CN2 GT (202.97 + 59.43)
	gtHops := []HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "202.97.22.1"},
		{Hop: 3, IP: "59.43.247.1"},
		{Hop: 4, IP: "154.22.1.1"},
	}
	name, rType, _ = ClassifyRoute(gtHops)
	if rType != "CN2_GT" {
		t.Errorf("expected CN2_GT, got %s (%s)", rType, name)
	}

	// 3. 163 (202.97 only)
	hops163 := []HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "202.97.22.1"},
		{Hop: 3, IP: "202.97.55.1"},
		{Hop: 4, IP: "154.22.1.1"},
	}
	name, rType, _ = ClassifyRoute(hops163)
	if rType != "163" {
		t.Errorf("expected 163, got %s (%s)", rType, name)
	}

	// 4. CU4837
	hops4837 := []HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "219.158.113.1"},
		{Hop: 3, IP: "154.22.1.1"},
	}
	name, rType, _ = ClassifyRoute(hops4837)
	if rType != "CU4837" {
		t.Errorf("expected CU4837, got %s (%s)", rType, name)
	}

	// 5. CU9929
	hops9929 := []HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "218.105.10.1"},
		{Hop: 3, IP: "154.22.1.1"},
	}
	name, rType, _ = ClassifyRoute(hops9929)
	if rType != "CU9929" {
		t.Errorf("expected CU9929, got %s (%s)", rType, name)
	}

	// 6. CMIN2
	hopsCMIN2 := []HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "223.120.22.1"},
		{Hop: 3, IP: "154.22.1.1"},
	}
	name, rType, _ = ClassifyRoute(hopsCMIN2)
	if rType != "CMIN2" {
		t.Errorf("expected CMIN2, got %s (%s)", rType, name)
	}

	// 7. CMI
	hopsCMI := []HopInfo{
		{Hop: 1, IP: "192.168.1.1"},
		{Hop: 2, IP: "221.183.55.1"},
		{Hop: 3, IP: "154.22.1.1"},
	}
	name, rType, _ = ClassifyRoute(hopsCMI)
	if rType != "CMI" {
		t.Errorf("expected CMI, got %s (%s)", rType, name)
	}
}
