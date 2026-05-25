package api

import "testing"

func TestClassifyResultTreatsTimeoutAsFailed(t *testing.T) {
	if got := classifyResult("timeout_killed: package exceeded 20m"); got != "failed" {
		t.Fatalf("classifyResult(timeout)=%q", got)
	}
}
