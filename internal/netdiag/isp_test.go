package netdiag

import (
	"context"
	"testing"
	"time"
)

func TestGetPublicISP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	isp, err := GetPublicISP(ctx)
	if err != nil {
		t.Skipf("skipping live network detection test: %v", err)
		return
	}
	if isp.IP == "" {
		t.Errorf("expected non-empty IP")
	}
}

func TestParseCipCCOutput(t *testing.T) {
	mock := `IP	: 1.2.3.4
地址	: 中国 浙江 杭州
运营商	: 电信
`
	info, err := parseCipCCOutput(mock)
	if err != nil {
		t.Fatalf("parseCipCCOutput failed: %v", err)
	}
	if info.IP != "1.2.3.4" || info.City != "杭州" || info.Type != ISPTelecom {
		t.Errorf("unexpected parsed info: %+v", info)
	}
}

func TestCategorizeISP(t *testing.T) {
	if cat := CategorizeISP("中国电信", "", "", "CN"); cat != ISPTelecom {
		t.Errorf("expected ISPTelecom, got %s", cat)
	}
	if cat := CategorizeISP("中国联通", "", "", "CN"); cat != ISPUnicom {
		t.Errorf("expected ISPUnicom, got %s", cat)
	}
	if cat := CategorizeISP("中国移动", "", "", "CN"); cat != ISPMobile {
		t.Errorf("expected ISPMobile, got %s", cat)
	}
	if cat := CategorizeISP("CERNET", "", "", "CN"); cat != ISPBroadnet {
		t.Errorf("expected ISPBroadnet, got %s", cat)
	}
	if cat := CategorizeISP("Comcast", "", "", "US"); cat != ISPOverseas {
		t.Errorf("expected ISPOverseas, got %s", cat)
	}
}
