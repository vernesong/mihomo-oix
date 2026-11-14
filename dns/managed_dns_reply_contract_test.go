package dns

import "testing"

func TestManagedDNSReplyContract(t *testing.T) {
	for _, vector := range dnsContractCases(t) {
		t.Run(vector.Name, func(t *testing.T) {
			query, err := contractMessage(t, vector.Query)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := contractMessage(t, vector.Response)
			verdict := "failure"
			if err == nil && oixRepliesTo(query, reply) {
				verdict = "positive"
				if isNegativeResponse(reply, query.Question[0]) {
					verdict = "negative"
				}
			}
			if verdict != vector.Verdict {
				t.Fatalf("verdict=%s want=%s", verdict, vector.Verdict)
			}
		})
	}
}
