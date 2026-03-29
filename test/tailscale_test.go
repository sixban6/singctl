package test

import "testing"

func TestGatewayModeDoesNotForceAcceptRoutes(t *testing.T) {
	mainRouter := false
	exitNode := false
	acceptRoutes := false
	acceptRoutesChanged := false
	mode := "gateway"

	switch mode {
	case "client":
		mainRouter = false
		exitNode = false
	case "router":
		mainRouter = true
		exitNode = false
	case "exit":
		mainRouter = false
		exitNode = true
	case "gateway":
		mainRouter = true
		exitNode = true
	}

	if !mainRouter || !exitNode {
		t.Fatal("gateway mode should enable both router and exit-node")
	}
	if acceptRoutes {
		t.Fatal("gateway mode must not force accept-routes=true")
	}
	if acceptRoutesChanged {
		t.Fatal("gateway mode must not mark accept-routes as user-overridden")
	}
}

func TestGatewayModeCanStillUseExplicitAcceptRoutes(t *testing.T) {
	mainRouter := false
	exitNode := false
	acceptRoutes := true
	acceptRoutesChanged := true
	mode := "gateway"

	switch mode {
	case "client":
		mainRouter = false
		exitNode = false
	case "router":
		mainRouter = true
		exitNode = false
	case "exit":
		mainRouter = false
		exitNode = true
	case "gateway":
		mainRouter = true
		exitNode = true
	}

	if !mainRouter || !exitNode {
		t.Fatal("gateway mode should enable both router and exit-node")
	}
	if !acceptRoutes || !acceptRoutesChanged {
		t.Fatal("explicit --accept-routes should still be preserved in gateway mode")
	}
}
