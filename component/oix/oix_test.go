package oix

import (
	"net/http"
	"testing"
)

func intPointer(value int) *int {
	return &value
}

func TestPlanQuery(t *testing.T) {
	tests := []struct {
		name string
		plan planIdentity
		want string
	}{
		{name: "no plan", plan: planIdentity{Code: "no_plan", Rank: intPointer(0)}, want: ""},
		{name: "iron", plan: planIdentity{Code: "iron", Rank: intPointer(10)}, want: ""},
		{name: "alu", plan: planIdentity{Code: "alu", Rank: intPointer(20)}, want: "?lv=2"},
		{name: "bronze", plan: planIdentity{Code: "bronze", Rank: intPointer(30)}, want: "?type=love"},
		{name: "silver", plan: planIdentity{Code: "silver", Rank: intPointer(40)}, want: "?type=love"},
		{name: "gold", plan: planIdentity{Code: "gold", Rank: intPointer(50)}, want: "?type=love"},
		{name: "stable rank wins", plan: planIdentity{Code: "iron", Rank: intPointer(30)}, want: "?type=love"},
		{name: "explicit zero rank wins", plan: planIdentity{Code: "iron", Rank: intPointer(0)}, want: ""},
		{name: "code fallback iron", plan: planIdentity{Code: "iron"}, want: ""},
		{name: "code fallback alu", plan: planIdentity{Code: "alu"}, want: "?lv=2"},
		{name: "code fallback silver", plan: planIdentity{Code: "silver"}, want: "?type=love"},
		{name: "code fallback gold", plan: planIdentity{Code: "gold"}, want: "?type=love"},
		{name: "legacy no plan", plan: planIdentity{Name: "no plan"}, want: ""},
		{name: "legacy iron", plan: planIdentity{Name: "Pass Iron"}, want: ""},
		{name: "legacy alu", plan: planIdentity{Name: "Pass Alu"}, want: "?lv=2"},
		{name: "legacy bronze", plan: planIdentity{Name: "Pass Bronze"}, want: "?lv=2"},
		{name: "legacy silver", plan: planIdentity{Name: "Pass Silver"}, want: "?type=love"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := planQuery(test.plan); got != test.want {
				t.Fatalf("planQuery(%+v) = %q, want %q", test.plan, got, test.want)
			}
		})
	}
}

func TestPlanIdentityFromResponseRejectsMissingData(t *testing.T) {
	_, err := planIdentityFromResponse(informationResponse{Ret: http.StatusOK})
	if err == nil {
		t.Fatal("expected missing information data to be rejected")
	}
}
