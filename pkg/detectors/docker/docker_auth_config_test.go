package docker

import (
	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"testing"
)

func TestDocker_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		// Kubernetes public test credentials
		// https://github.com/kubernetes/autoscaler/blob/f22b40eab867cbc52bdb15dc8768962e21d22837/vertical-pod-autoscaler/e2e/vendor/k8s.io/kubernetes/test/e2e/common/node/runtime.go#L283C1-L290C2
		{
			name: "GCP auth",
			input: `{
	"auths": {
		"https://gcr.io": {
			"auth": "X2pzb25fa2V5OnsKICAidHlwZSI6ICJzZXJ2aWNlX2FjY291bnQiLAogICJwcm9qZWN0X2lkIjogImF1dGhlbnRpY2F0ZWQtaW1hZ2UtcHVsbGluZyIsCiAgInByaXZhdGVfa2V5X2lkIjogImI5ZjJhNjY0YWE5YjIwNDg0Y2MxNTg2MDYzZmVmZGExOTIyNGFjM2IiLAogICJwcml2YXRlX2tleSI6ICItLS0tLUJFR0lOIFBSSVZBVEUgS0VZLS0tLS1cbk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQzdTSG5LVEVFaVlMamZcbkpmQVBHbUozd3JCY2VJNTBKS0xxS21GWE5RL3REWGJRK2g5YVl4aldJTDhEeDBKZTc0bVovS01uV2dYRjVLWlNcbm9BNktuSU85Yi9SY1NlV2VpSXRSekkzL1lYVitPNkNjcmpKSXl4anFWam5mVzJpM3NhMzd0OUE5VEZkbGZycm5cbjR6UkpiOWl4eU1YNGJMdHFGR3ZCMDNOSWl0QTNzVlo1ODhrb1FBZmgzSmhhQmVnTWorWjRSYko0aGVpQlFUMDNcbnZVbzViRWFQZVQ5RE16bHdzZWFQV2dydDZOME9VRGNBRTl4bGNJek11MjUzUG4vSzgySFpydEx4akd2UkhNVXhcbng0ZjhwSnhmQ3h4QlN3Z1NORit3OWpkbXR2b0wwRmE3ZGducFJlODZWRDY2ejNZenJqNHlLRXRqc2hLZHl5VWRcbkl5cVhoN1JSQWdNQkFBRUNnZ0VBT3pzZHdaeENVVlFUeEFka2wvSTVTRFVidi9NazRwaWZxYjJEa2FnbmhFcG9cbjFJajJsNGlWMTByOS9uenJnY2p5VlBBd3pZWk1JeDFBZVF0RDdoUzRHWmFweXZKWUc3NkZpWFpQUm9DVlB6b3VcbmZyOGRDaWFwbDV0enJDOWx2QXNHd29DTTdJWVRjZmNWdDdjRTEyRDNRS3NGNlo3QjJ6ZmdLS251WVBmK0NFNlRcbmNNMHkwaCtYRS9kMERvSERoVy96YU1yWEhqOFRvd2V1eXRrYmJzNGYvOUZqOVBuU2dET1lQd2xhbFZUcitGUWFcbkpSd1ZqVmxYcEZBUW14M0Jyd25rWnQzQ2lXV2lGM2QrSGk5RXRVYnRWclcxYjZnK1JRT0licWFtcis4YlJuZFhcbjZWZ3FCQWtKWjhSVnlkeFVQMGQxMUdqdU9QRHhCbkhCbmM0UW9rSXJFUUtCZ1FEMUNlaWN1ZGhXdGc0K2dTeGJcbnplanh0VjFONDFtZHVjQnpvMmp5b1dHbzNQVDh3ckJPL3lRRTM0cU9WSi9pZCs4SThoWjRvSWh1K0pBMDBzNmdcblRuSXErdi9kL1RFalk4MW5rWmlDa21SUFdiWHhhWXR4UjIxS1BYckxOTlFKS2ttOHRkeVh5UHFsOE1veUdmQ1dcbjJ2aVBKS05iNkhabnY5Q3lqZEo5ZzJMRG5RS0JnUUREcVN2eURtaGViOTIzSW96NGxlZ01SK205Z2xYVWdTS2dcbkVzZlllbVJmbU5XQitDN3ZhSXlVUm1ZNU55TXhmQlZXc3dXRldLYXhjK0krYnFzZmx6elZZdFpwMThNR2pzTURcbmZlZWZBWDZCWk1zVXQ3Qmw3WjlWSjg1bnRFZHFBQ0xwWitaLzN0SVJWdWdDV1pRMWhrbmxHa0dUMDI0SkVFKytcbk55SDFnM2QzUlFLQmdRQ1J2MXdKWkkwbVBsRklva0tGTkh1YTBUcDNLb1JTU1hzTURTVk9NK2xIckcxWHJtRjZcbkMwNGNTKzQ0N0dMUkxHOFVUaEpKbTRxckh0Ti9aK2dZOTYvMm1xYjRIakpORDM3TVhKQnZFYTN5ZUxTOHEvK1JcbjJGOU1LamRRaU5LWnhQcG84VzhOSlREWTVOa1BaZGh4a2pzSHdVNGRTNjZwMVRESUU0MGd0TFpaRFFLQmdGaldcbktyblFpTnEzOS9iNm5QOFJNVGJDUUFKbmR3anhTUU5kQTVmcW1rQTlhRk9HbCtqamsxQ1BWa0tNSWxLSmdEYkpcbk9heDl2OUc2Ui9NSTFIR1hmV3QxWU56VnRocjRIdHNyQTB0U3BsbWhwZ05XRTZWejZuQURqdGZQSnMyZUdqdlhcbmpQUnArdjhjY21MK3dTZzhQTGprM3ZsN2VlNXJsWWxNQndNdUdjUHhBb0dBZWRueGJXMVJMbVZubEFpSEx1L0xcbmxtZkF3RFdtRWlJMFVnK1BMbm9Pdk81dFE1ZDRXMS94RU44bFA0cWtzcGtmZk1Rbk5oNFNZR0VlQlQzMlpxQ1RcbkpSZ2YwWGpveXZ2dXA5eFhqTWtYcnBZL3ljMXpmcVRaQzBNTzkvMVVjMWJSR2RaMmR5M2xSNU5XYXA3T1h5Zk9cblBQcE5Gb1BUWGd2M3FDcW5sTEhyR3pNPVxuLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLVxuIiwKICAiY2xpZW50X2VtYWlsIjogImltYWdlLXB1bGxpbmdAYXV0aGVudGljYXRlZC1pbWFnZS1wdWxsaW5nLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAiY2xpZW50X2lkIjogIjExMzc5NzkxNDUzMDA3MzI3ODcxMiIsCiAgImF1dGhfdXJpIjogImh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi9hdXRoIiwKICAidG9rZW5fdXJpIjogImh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi90b2tlbiIsCiAgImF1dGhfcHJvdmlkZXJfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9vYXV0aDIvdjEvY2VydHMiLAogICJjbGllbnRfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9yb2JvdC92MS9tZXRhZGF0YS94NTA5L2ltYWdlLXB1bGxpbmclNDBhdXRoZW50aWNhdGVkLWltYWdlLXB1bGxpbmcuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iCn0=",
			"email": "image-pulling@authenticated-image-pulling.iam.gserviceaccount.com"
		}
	}
}`,
			want: []string{"https://gcr.io:X2pzb25fa2V5OnsKICAidHlwZSI6ICJzZXJ2aWNlX2FjY291bnQiLAogICJwcm9qZWN0X2lkIjogImF1dGhlbnRpY2F0ZWQtaW1hZ2UtcHVsbGluZyIsCiAgInByaXZhdGVfa2V5X2lkIjogImI5ZjJhNjY0YWE5YjIwNDg0Y2MxNTg2MDYzZmVmZGExOTIyNGFjM2IiLAogICJwcml2YXRlX2tleSI6ICItLS0tLUJFR0lOIFBSSVZBVEUgS0VZLS0tLS1cbk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQzdTSG5LVEVFaVlMamZcbkpmQVBHbUozd3JCY2VJNTBKS0xxS21GWE5RL3REWGJRK2g5YVl4aldJTDhEeDBKZTc0bVovS01uV2dYRjVLWlNcbm9BNktuSU85Yi9SY1NlV2VpSXRSekkzL1lYVitPNkNjcmpKSXl4anFWam5mVzJpM3NhMzd0OUE5VEZkbGZycm5cbjR6UkpiOWl4eU1YNGJMdHFGR3ZCMDNOSWl0QTNzVlo1ODhrb1FBZmgzSmhhQmVnTWorWjRSYko0aGVpQlFUMDNcbnZVbzViRWFQZVQ5RE16bHdzZWFQV2dydDZOME9VRGNBRTl4bGNJek11MjUzUG4vSzgySFpydEx4akd2UkhNVXhcbng0ZjhwSnhmQ3h4QlN3Z1NORit3OWpkbXR2b0wwRmE3ZGducFJlODZWRDY2ejNZenJqNHlLRXRqc2hLZHl5VWRcbkl5cVhoN1JSQWdNQkFBRUNnZ0VBT3pzZHdaeENVVlFUeEFka2wvSTVTRFVidi9NazRwaWZxYjJEa2FnbmhFcG9cbjFJajJsNGlWMTByOS9uenJnY2p5VlBBd3pZWk1JeDFBZVF0RDdoUzRHWmFweXZKWUc3NkZpWFpQUm9DVlB6b3VcbmZyOGRDaWFwbDV0enJDOWx2QXNHd29DTTdJWVRjZmNWdDdjRTEyRDNRS3NGNlo3QjJ6ZmdLS251WVBmK0NFNlRcbmNNMHkwaCtYRS9kMERvSERoVy96YU1yWEhqOFRvd2V1eXRrYmJzNGYvOUZqOVBuU2dET1lQd2xhbFZUcitGUWFcbkpSd1ZqVmxYcEZBUW14M0Jyd25rWnQzQ2lXV2lGM2QrSGk5RXRVYnRWclcxYjZnK1JRT0licWFtcis4YlJuZFhcbjZWZ3FCQWtKWjhSVnlkeFVQMGQxMUdqdU9QRHhCbkhCbmM0UW9rSXJFUUtCZ1FEMUNlaWN1ZGhXdGc0K2dTeGJcbnplanh0VjFONDFtZHVjQnpvMmp5b1dHbzNQVDh3ckJPL3lRRTM0cU9WSi9pZCs4SThoWjRvSWh1K0pBMDBzNmdcblRuSXErdi9kL1RFalk4MW5rWmlDa21SUFdiWHhhWXR4UjIxS1BYckxOTlFKS2ttOHRkeVh5UHFsOE1veUdmQ1dcbjJ2aVBKS05iNkhabnY5Q3lqZEo5ZzJMRG5RS0JnUUREcVN2eURtaGViOTIzSW96NGxlZ01SK205Z2xYVWdTS2dcbkVzZlllbVJmbU5XQitDN3ZhSXlVUm1ZNU55TXhmQlZXc3dXRldLYXhjK0krYnFzZmx6elZZdFpwMThNR2pzTURcbmZlZWZBWDZCWk1zVXQ3Qmw3WjlWSjg1bnRFZHFBQ0xwWitaLzN0SVJWdWdDV1pRMWhrbmxHa0dUMDI0SkVFKytcbk55SDFnM2QzUlFLQmdRQ1J2MXdKWkkwbVBsRklva0tGTkh1YTBUcDNLb1JTU1hzTURTVk9NK2xIckcxWHJtRjZcbkMwNGNTKzQ0N0dMUkxHOFVUaEpKbTRxckh0Ti9aK2dZOTYvMm1xYjRIakpORDM3TVhKQnZFYTN5ZUxTOHEvK1JcbjJGOU1LamRRaU5LWnhQcG84VzhOSlREWTVOa1BaZGh4a2pzSHdVNGRTNjZwMVRESUU0MGd0TFpaRFFLQmdGaldcbktyblFpTnEzOS9iNm5QOFJNVGJDUUFKbmR3anhTUU5kQTVmcW1rQTlhRk9HbCtqamsxQ1BWa0tNSWxLSmdEYkpcbk9heDl2OUc2Ui9NSTFIR1hmV3QxWU56VnRocjRIdHNyQTB0U3BsbWhwZ05XRTZWejZuQURqdGZQSnMyZUdqdlhcbmpQUnArdjhjY21MK3dTZzhQTGprM3ZsN2VlNXJsWWxNQndNdUdjUHhBb0dBZWRueGJXMVJMbVZubEFpSEx1L0xcbmxtZkF3RFdtRWlJMFVnK1BMbm9Pdk81dFE1ZDRXMS94RU44bFA0cWtzcGtmZk1Rbk5oNFNZR0VlQlQzMlpxQ1RcbkpSZ2YwWGpveXZ2dXA5eFhqTWtYcnBZL3ljMXpmcVRaQzBNTzkvMVVjMWJSR2RaMmR5M2xSNU5XYXA3T1h5Zk9cblBQcE5Gb1BUWGd2M3FDcW5sTEhyR3pNPVxuLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLVxuIiwKICAiY2xpZW50X2VtYWlsIjogImltYWdlLXB1bGxpbmdAYXV0aGVudGljYXRlZC1pbWFnZS1wdWxsaW5nLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAiY2xpZW50X2lkIjogIjExMzc5NzkxNDUzMDA3MzI3ODcxMiIsCiAgImF1dGhfdXJpIjogImh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi9hdXRoIiwKICAidG9rZW5fdXJpIjogImh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi90b2tlbiIsCiAgImF1dGhfcHJvdmlkZXJfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9vYXV0aDIvdjEvY2VydHMiLAogICJjbGllbnRfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9yb2JvdC92MS9tZXRhZGF0YS94NTA5L2ltYWdlLXB1bGxpbmclNDBhdXRoZW50aWNhdGVkLWltYWdlLXB1bGxpbmcuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iCn0="},
		},
		// Relies on the base64 decoder, which isn't present in this test (yet?)
		//		{
		//			name: "kubernetes .dockerconfigjson",
		//			input: `apiVersion: v1
		//data:
		// .dockerconfigjson: eyJhdXRocyI6eyJodHRwczovL2djci5pbyI6eyJ1c2VybmFtZSI6Il9qc29uX2tleSIsInBhc3N3b3JkIjoie1xuICBcInR5cGVcIjogXCJzZXJ2aWNlX2FjY291bnRcIixcbiAgXCJwcm9qZWN0X2lkXCI6IFwiY29uc3RhbnQtY3ViaXN0LTE3MzEyM1wiLFxuICBcInByaXZhdGVfa2V5X2lkXCI6IFwiYWRiMzY3M2NiOTkzNzkyNjZiY2MxZDU1YmIxZTdiZDFlYzM5NGI1Y1wiLFxuICBcInByaXZhdGVfa2V5XCI6IFwiLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXFxuTUlJRXZRSUJBREFOQmdrcWhraUc5dzBCQVFFRkFBU0NCS2N3Z2dTakFnRUFBb0lCQVFDNm8zN0o4S2kxUWp3RVxcbnhNT3ROUVZaK2xsWUxIdlNXV2tDeXp1a3JwbHdZRU9KRk5VR00yQ3NySHpjM0pDUDhGYWo1RVRHMjlvT1pLVkJcXG5MSjU3eVdKSEpyekhIb2JyOHNsNytpcjRjYUovSzNiS2lybmZWYTZFeXk5azFIa0RMSlZ4T1lsaXFTbkdtRlZ5XFxuQ3lpYXltNTI1V3VqanZIQkRaZUdsYzlqb1RLMG9yQXYvUCthZzhleUUvY05DS0FwTkk4ZTFXYmlhMFNCdWEwblxcblVZbFB1RXRxdzJ3NDhJbkh6akVQY0VmdENzWjBOZGhkY3hTdVNuSVB5NW9ua2JuVXhZWnAzUjF3TmQ3eDdaQk5cXG5ESmFCWEJTMlVkR1M0ditzeWJVQlU1aXFBckRNbVNmWUwxN09TU3ZzdEZSdVEydkJaa0M3TU96RWd2MUlIZjBXXFxubzlOSzBFaHZBZ01CQUFFQ2dnRUFDUm1MbkZaSzJORHFrdU9kRkJ3dnIwYTdoY2NLeW5pOWhxWURaSERNTTduSVxcbmU5aUkxN2ZpNWgyMWdNeVM1OUcwc21KTGV0UDJwUmtCemFtdjdjMGwwNGp2VDFpM3IxZ0pFWU1Oc1V0VHZFRG1cXG42OUorWkRDTjc3K1FYS21DQ2tZKzRHUmVieHhjV0doNC9MUjZrd0Y5Qi9oV1JTL2xBdlZNc1ZmVjRyK3JTZVNjXFxubU1KOTRBUTROM3hyV0VRc3Vpd1ZIZldMdElMTWZGN1JoV3VzdjJiZ1gvRCs0ajdISHRoODVrYlcxSzR0MnFkN1xcbkIwaEJEcVlQTEtjYzJVNkNJR0NRZ1h3THNlYUUxRkptYWpsdnNVK0pXdmY2MmZTNk8wSlVMeVFLMzZkczZkRlJcXG5qaDg1TWJsZVlHMWdpaFpPTXJtcENvWklUazdFT01lU2pQZ0VaWG5pVVFLQmdRRDNtUHJrZmVKVWNXWmpNZndCXFxuYnJJNE1NRWl2R1JJVDR5RzZxZHZpZFIrd1U3djMxbG1Oa1A3S2s4K1hoQWtGMk1pQkRSakFGVm8rNHQ3a3paRFxcbk45Zk9NSlgwakZnUVpLajFuR1gxekZ2ZERqRTh3ZWRTN2ZMV3BOczJlZm5GWUpQRm5SRU16eG81VWpGNTZ4V1pcXG5ZQmI2VHlNaTNRa1lEblA0WTVjTUZCVUpiUUtCZ1FEQStPNDlUc2EyYWdWUnJYbC8xRDNzWHd0UjdKSGhuRURkXFxuNWlZM0FtOVQxV2pVVTE1T2lwTUxOaXpBb3lRWGlKRVlaMmNuRHZnbHdkNEsvMWFLbityc3hzWUdFZjhoWVBIclxcbkJoN3FueW44SzJseTJoakUxY0xpVFg4NEVnd1VMcFJjeGo3bkM0ZWFLOEdJeUdLNnZrR3NoNCs1bnJLVFlkaUtcXG5MeUhSMUc2cnl3S0JnUURnLzJqSGFNbmEySzRsYUUvTWNXNk05MmtiQ3IzS3BGZGNaeksrZmk3Vy9RMmhsNEtqXFxuQ3A4ZVNDVjQxSHV3Z0h3NmRqMncxYVhINEFheHhtWWlFVVlQL2tEVzJRNVIzMWRXMHNnbzVJdDZSeUpoUndmU1xcbmFaOHFoT2NjQ3gzNXlqaWU5SXVBNjFhMlRrWGR0ODZKOFRNUVJnZjA3NDRMQ1Y5RGtpUzUraW5meFFLQmdFMVdcXG5ObHlacXFmR203VWRPZmxSL1RNeThCMTRHd3I1RFVJaEQ2V3lNeDI5QkpNN2lpc2QvRXBjL3RpQlNXQ3BHY1ZYXFxuQTQ4eXY1NmFNTHZsa3pCaFlNeGQ2VlRiZDQxUUJnUXo0c1lTM2Nlek9rS09SNmp6Sm5SOXJJT3pMK1lTdU9EcFxcbmpxSVlDOU5zdjlacXdLNm91emRDNlFYeUpRMU9CSE4wNmkvbTNDZTdBb0dBU01wRStscDlxV2ZWYXlGV2tlWVBcXG5OOFhId2FNUWNkT0ZkbDZFdlF0ZWtQY0xiQ1F6UzRSdEhBT01NTDN5ci9DQUk5SmZkanhWMHdicW1oNlJ3WFAzXFxuKzhkOVJpNjhsMGV3NUhLMDJWRHFhZE8vOTJhaHNrNmYxV1ZOL0dMcFg4Yk9NZEZFdnJOS09zUVk0RW9DV0JTa1xcblF1ZmRBdFZueE1UZG9ydTNxY0N4RG1vPVxcbi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS1cXG5cIixcbiAgXCJjbGllbnRfZW1haWxcIjogXCJrZi1hY2NvdW50QGNvbnN0YW50LWN1YmlzdC0xNzMxMjMuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb21cIixcbiAgXCJjbGllbnRfaWRcIjogXCIxMDkyODcyODAxMzE5ODQ2MTA2MTZcIixcbiAgXCJhdXRoX3VyaVwiOiBcImh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi9hdXRoXCIsXG4gIFwidG9rZW5fdXJpXCI6IFwiaHR0cHM6Ly9vYXV0aDIuZ29vZ2xlYXBpcy5jb20vdG9rZW5cIixcbiAgXCJhdXRoX3Byb3ZpZGVyX3g1MDlfY2VydF91cmxcIjogXCJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9vYXV0aDIvdjEvY2VydHNcIixcbiAgXCJjbGllbnRfeDUwOV9jZXJ0X3VybFwiOiBcImh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL3JvYm90L3YxL21ldGFkYXRhL3g1MDkva2YtYWNjb3VudCU0MGNvbnN0YW50LWN1YmlzdC0xNzMxMjMuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb21cIlxufSIsImVtYWlsIjoia2YtYWNjb3VudEBjb25zdGFudC1jdWJpc3QtMTczMTIzLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwiYXV0aCI6IlgycHpiMjVmYTJWNU9uc0tJQ0FpZEhsd1pTSTZJQ0p6WlhKMmFXTmxYMkZqWTI5MWJuUWlMQW9nSUNKd2NtOXFaV04wWDJsa0lqb2dJbU52Ym5OMFlXNTBMV04xWW1semRDMHhOek14TWpNaUxBb2dJQ0p3Y21sMllYUmxYMnRsZVY5cFpDSTZJQ0poWkdJek5qY3pZMkk1T1RNM09USTJObUpqWXpGa05UVmlZakZsTjJKa01XVmpNemswWWpWaklpd0tJQ0FpY0hKcGRtRjBaVjlyWlhraU9pQWlMUzB0TFMxQ1JVZEpUaUJRVWtsV1FWUkZJRXRGV1MwdExTMHRYRzVOU1VsRmRsRkpRa0ZFUVU1Q1oydHhhR3RwUnpsM01FSkJVVVZHUVVGVFEwSkxZM2RuWjFOcVFXZEZRVUZ2U1VKQlVVTTJiek0zU2poTGFURlJhbmRGWEc1NFRVOTBUbEZXV2l0c2JGbE1TSFpUVjFkclEzbDZkV3R5Y0d4M1dVVlBTa1pPVlVkTk1rTnpja2g2WXpOS1ExQTRSbUZxTlVWVVJ6STViMDlhUzFaQ1hHNU1TalUzZVZkS1NFcHlla2hJYjJKeU9ITnNOeXRwY2pSallVb3ZTek5pUzJseWJtWldZVFpGZVhrNWF6RklhMFJNU2xaNFQxbHNhWEZUYmtkdFJsWjVYRzVEZVdsaGVXMDFNalZYZFdwcWRraENSRnBsUjJ4ak9XcHZWRXN3YjNKQmRpOVFLMkZuT0dWNVJTOWpUa05MUVhCT1NUaGxNVmRpYVdFd1UwSjFZVEJ1WEc1VldXeFFkVVYwY1hjeWR6UTRTVzVJZW1wRlVHTkZablJEYzFvd1RtUm9aR040VTNWVGJrbFFlVFZ2Ym10aWJsVjRXVnB3TTFJeGQwNWtOM2czV2tKT1hHNUVTbUZDV0VKVE1sVmtSMU0wZGl0emVXSlZRbFUxYVhGQmNrUk5iVk5tV1V3eE4wOVRVM1p6ZEVaU2RWRXlka0phYTBNM1RVOTZSV2QyTVVsSVpqQlhYRzV2T1U1TE1FVm9ka0ZuVFVKQlFVVkRaMmRGUVVOU2JVeHVSbHBMTWs1RWNXdDFUMlJHUW5kMmNqQmhOMmhqWTB0NWJtazVhSEZaUkZwSVJFMU5OMjVKWEc1bE9XbEpNVGRtYVRWb01qRm5UWGxUTlRsSE1ITnRTa3hsZEZBeWNGSnJRbnBoYlhZM1l6QnNNRFJxZGxReGFUTnlNV2RLUlZsTlRuTlZkRlIyUlVSdFhHNDJPVW9yV2tSRFRqYzNLMUZZUzIxRFEydFpLelJIVW1WaWVIaGpWMGRvTkM5TVVqWnJkMFk1UWk5b1YxSlRMMnhCZGxaTmMxWm1WalJ5SzNKVFpWTmpYRzV0VFVvNU5FRlJORTR6ZUhKWFJWRnpkV2wzVmtobVYweDBTVXhOWmtZM1VtaFhkWE4yTW1KbldDOUVLelJxTjBoSWRHZzROV3RpVnpGTE5IUXljV1EzWEc1Q01HaENSSEZaVUV4TFkyTXlWVFpEU1VkRFVXZFlkMHh6WldGRk1VWktiV0ZxYkhaelZTdEtWM1ptTmpKbVV6WlBNRXBWVEhsUlN6TTJaSE0yWkVaU1hHNXFhRGcxVFdKc1pWbEhNV2RwYUZwUFRYSnRjRU52V2tsVWF6ZEZUMDFsVTJwUVowVmFXRzVwVlZGTFFtZFJSRE50VUhKclptVktWV05YV21wTlpuZENYRzVpY2trMFRVMUZhWFpIVWtsVU5IbEhObkZrZG1sa1VpdDNWVGQyTXpGc2JVNXJVRGRMYXpncldHaEJhMFl5VFdsQ1JGSnFRVVpXYnlzMGREZHJlbHBFWEc1T09XWlBUVXBZTUdwR1oxRmFTMm94YmtkWU1YcEdkbVJFYWtVNGQyVmtVemRtVEZkd1RuTXlaV1p1UmxsS1VFWnVVa1ZOZW5odk5WVnFSalUyZUZkYVhHNVpRbUkyVkhsTmFUTlJhMWxFYmxBMFdUVmpUVVpDVlVwaVVVdENaMUZFUVN0UE5EbFVjMkV5WVdkV1VuSlliQzh4UkROeldIZDBVamRLU0dodVJVUmtYRzQxYVZrelFXMDVWREZYYWxWVk1UVlBhWEJOVEU1cGVrRnZlVkZZYVVwRldWb3lZMjVFZG1kc2QyUTBTeTh4WVV0dUszSnplSE5aUjBWbU9HaFpVRWh5WEc1Q2FEZHhibmx1T0VzeWJIa3lhR3BGTVdOTWFWUllPRFJGWjNkVlRIQlNZM2hxTjI1RE5HVmhTemhIU1hsSFN6WjJhMGR6YURRck5XNXlTMVJaWkdsTFhHNU1lVWhTTVVjMmNubDNTMEpuVVVSbkx6SnFTR0ZOYm1FeVN6UnNZVVV2VFdOWE5rMDVNbXRpUTNJelMzQkdaR05hZWtzclptazNWeTlSTW1oc05FdHFYRzVEY0RobFUwTldOREZJZFhkblNIYzJaR295ZHpGaFdFZzBRV0Y0ZUcxWmFVVlZXVkF2YTBSWE1sRTFVak14WkZjd2MyZHZOVWwwTmxKNVNtaFNkMlpUWEc1aFdqaHhhRTlqWTBONE16VjVhbWxsT1VsMVFUWXhZVEpVYTFoa2REZzJTamhVVFZGU1oyWXdOelEwVEVOV09VUnJhVk0xSzJsdVpuaFJTMEpuUlRGWFhHNU9iSGxhY1hGbVIyMDNWV1JQWm14U0wxUk5lVGhDTVRSSGQzSTFSRlZKYUVRMlYzbE5lREk1UWtwTk4ybHBjMlF2UlhCakwzUnBRbE5YUTNCSFkxWllYRzVCTkRoNWRqVTJZVTFNZG14cmVrSm9XVTE0WkRaV1ZHSmtOREZSUW1kUmVqUnpXVk16WTJWNlQydExUMUkyYW5wS2JsSTVja2xQZWt3cldWTjFUMFJ3WEc1cWNVbFpRemxPYzNZNVduRjNTelp2ZFhwa1F6WlJXSGxLVVRGUFFraE9NRFpwTDIwelEyVTNRVzlIUVZOTmNFVXJiSEE1Y1ZkbVZtRjVSbGRyWlZsUVhHNU9PRmhJZDJGTlVXTmtUMFprYkRaRmRsRjBaV3RRWTB4aVExRjZVelJTZEVoQlQwMU5URE41Y2k5RFFVazVTbVprYW5oV01IZGljVzFvTmxKM1dGQXpYRzRyT0dRNVVtazJPR3d3WlhjMVNFc3dNbFpFY1dGa1R5ODVNbUZvYzJzMlpqRlhWazR2UjB4d1dEaGlUMDFrUmtWMmNrNUxUM05SV1RSRmIwTlhRbE5yWEc1UmRXWmtRWFJXYm5oTlZHUnZjblV6Y1dORGVFUnRiejFjYmkwdExTMHRSVTVFSUZCU1NWWkJWRVVnUzBWWkxTMHRMUzFjYmlJc0NpQWdJbU5zYVdWdWRGOWxiV0ZwYkNJNklDSnJaaTFoWTJOdmRXNTBRR052Ym5OMFlXNTBMV04xWW1semRDMHhOek14TWpNdWFXRnRMbWR6WlhKMmFXTmxZV05qYjNWdWRDNWpiMjBpTEFvZ0lDSmpiR2xsYm5SZmFXUWlPaUFpTVRBNU1qZzNNamd3TVRNeE9UZzBOakV3TmpFMklpd0tJQ0FpWVhWMGFGOTFjbWtpT2lBaWFIUjBjSE02THk5aFkyTnZkVzUwY3k1bmIyOW5iR1V1WTI5dEwyOHZiMkYxZEdneUwyRjFkR2dpTEFvZ0lDSjBiMnRsYmw5MWNta2lPaUFpYUhSMGNITTZMeTl2WVhWMGFESXVaMjl2WjJ4bFlYQnBjeTVqYjIwdmRHOXJaVzRpTEFvZ0lDSmhkWFJvWDNCeWIzWnBaR1Z5WDNnMU1EbGZZMlZ5ZEY5MWNtd2lPaUFpYUhSMGNITTZMeTkzZDNjdVoyOXZaMnhsWVhCcGN5NWpiMjB2YjJGMWRHZ3lMM1l4TDJObGNuUnpJaXdLSUNBaVkyeHBaVzUwWDNnMU1EbGZZMlZ5ZEY5MWNtd2lPaUFpYUhSMGNITTZMeTkzZDNjdVoyOXZaMnhsWVhCcGN5NWpiMjB2Y205aWIzUXZkakV2YldWMFlXUmhkR0V2ZURVd09TOXJaaTFoWTJOdmRXNTBKVFF3WTI5dWMzUmhiblF0WTNWaWFYTjBMVEUzTXpFeU15NXBZVzB1WjNObGNuWnBZMlZoWTJOdmRXNTBMbU52YlNJS2ZRPT0ifX19
		//kind: Secret
		//metadata:
		// name: docker-secret
		//type: kubernetes.io/dockerconfigjson`,
		//			want: []string{"3aBcDFE5678901234567890_1a2b3c4d"},
		//		},
		{
			name: "DOCKER_AUTH_CONFIG escaped",
			input: `[[runners]]
  name = "docker-test@236"
  url = "http://10.88.26.237:80"
  executor = "docker"
  environment = ["DOCKER_AUTH_CONFIG={\"auths\":{\"docker.contoso.com.tw:8083\":{\"auth\":\"c2Zjcy50ZXN0ZXI6c2Zjcw==\"}}}"]
  [runners.custom_build_dir]
  [runners.cache]
    Insecure = false`,
			want: []string{"docker.contoso.com.tw:8083:c2Zjcy50ZXN0ZXI6c2Zjcw=="},
		},
		{
			name: "DOCKER_AUTH_CONFIG",
			input: `variables:
  DOCKER_DRIVER: overlay2
  DOCKER_AUTH_CONFIG: '{"auths": {"local-docker.artifactory.university.edu.au": {"auth": "YmFtYm9vOmpoMkh6UnNRU3pad3liaDc="}}}'
`,
			want: []string{"local-docker.artifactory.university.edu.au:YmFtYm9vOmpoMkh6UnNRU3pad3liaDc="},
		},
		{
			name: "empty email string",
			input: `{
  "auths": {
    "quay.io": {
      "auth": "dHJ1ZmZsZWhvZzpiZDQyNzQ2Yy1hNzc3LTQ4ZDktYjBhMi04N2I2YzEzMjdkMDA=",
      "email": ""
    }
  }
}`,
			want: []string{"quay.io:dHJ1ZmZsZWhvZzpiZDQyNzQ2Yy1hNzc3LTQ4ZDktYjBhMi04N2I2YzEzMjdkMDA="},
		},
		{
			name:  "docker.io registry",
			input: `{"auths":{"docker.io":{"auth": "dHJ1ZmZsZWhvZzpiZDQyNzQ2Yy1hNzc3LTQ4ZDktYjBhMi04N2I2YzEzMjdkMDA="}}}`,
			want:  []string{"index.docker.io:dHJ1ZmZsZWhvZzpiZDQyNzQ2Yy1hNzc3LTQ4ZDktYjBhMi04N2I2YzEzMjdkMDA="},
		},
		{
			name:  "registry with slashes",
			input: `{"auths":{"https://index.docker.io/v1/":{"auth": "dHJ1ZmZsZWhvZzpiZDQyNzQ2Yy1hNzc3LTQ4ZDktYjBhMi04N2I2YzEzMjdkMDA="}}}`,
			want:  []string{"https://index.docker.io/v1/:dHJ1ZmZsZWhvZzpiZDQyNzQ2Yy1hNzc3LTQ4ZDktYjBhMi04N2I2YzEzMjdkMDA="},
		},
		{
			name:  "literal newlines",
			input: `{\n\"auths\": {\n\"registry.company.com\": {\n\"username\": \"conexp\",\n\"password\": \"FTA@CNCF0n@zure3\",\n\"email\": \"user@mycompany.com\",\n\"auth\": \"Y29uZXhwOkZUQUBDTkNGMG5AenVyZTM=\"\n}\n}\n}\n`,
			want:  []string{"registry.company.com:Y29uZXhwOkZUQUBDTkNGMG5AenVyZTM="},
		},
		{
			name:  "literal newlines and tabs",
			input: `  config.json: "{\n\t\"auths\": {\n\t\t\"https://index.docker.io/v1/\": {\n\t\t\t\"auth\":\"Y29uZXhwOkZUQUBDTkNGMG5AenVyZTM=\"\n\t\t}\n\t}\n}"`,
			want:  []string{"https://index.docker.io/v1/:Y29uZXhwOkZUQUBDTkNGMG5AenVyZTM="},
		},
		{
			name: "content after last }",
			// This is base64-encoded, however, that doesn't get detected in these tests.
			//input: `{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1","request":{"uid":"b9d17c49-1b2c-421a-8ae8-3b3d252d2f61","kind":{"group":"","version":"v1","kind":"Secret"},"resource":{"group":"","version":"v1","resource":"secrets"},"requestKind":{"group":"","version":"v1","kind":"Secret"},"requestResource":{"group":"","version":"v1","resource":"secrets"},"name":"regcred","namespace":"test-webhooks","operation":"CREATE","userInfo":{"username":"kube:admin","groups":["system:cluster-admins","system:authenticated"],"extra":{"scopes.authorization.openshift.io":["user:full"]}},"object":{"kind":"Secret","apiVersion":"v1","metadata":{"name":"regcred","namespace":"test-webhooks","uid":"544674ac-f0fb-4a30-994b-eab579e1f418","creationTimestamp":"2022-05-03T15:16:55Z","managedFields":[{"manager":"kubectl-create","operation":"Update","apiVersion":"v1","time":"2022-05-03T15:16:55Z","fieldsType":"FieldsV1","fieldsV1":{"f:data":{".":{},"f:.dockerconfigjson":{}},"f:type":{}}}]},"data":{".dockerconfigjson":"eyJhdXRocyI6eyJxdWF5LmlvIjp7InVzZXJuYW1lIjoiMTIzIiwicGFzc3dvcmQiOiIxMjMiLCJhdXRoIjoiTVRJek9qRXlNdz09In19fQ=="},"type":"kubernetes.io/dockerconfigjson"},"oldObject":null,"dryRun":false,"options":{"kind":"CreateOptions","apiVersion":"meta.k8s.io/v1","fieldManager":"kubectl-create"}}}`,
			input: `{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1","request":{"uid":"b9d17c49-1b2c-421a-8ae8-3b3d252d2f61","kind":{"group":"","version":"v1","kind":"Secret"},"resource":{"group":"","version":"v1","resource":"secrets"},"requestKind":{"group":"","version":"v1","kind":"Secret"},"requestResource":{"group":"","version":"v1","resource":"secrets"},"name":"regcred","namespace":"test-webhooks","operation":"CREATE","userInfo":{"username":"kube:admin","groups":["system:cluster-admins","system:authenticated"],"extra":{"scopes.authorization.openshift.io":["user:full"]}},"object":{"kind":"Secret","apiVersion":"v1","metadata":{"name":"regcred","namespace":"test-webhooks","uid":"544674ac-f0fb-4a30-994b-eab579e1f418","creationTimestamp":"2022-05-03T15:16:55Z","managedFields":[{"manager":"kubectl-create","operation":"Update","apiVersion":"v1","time":"2022-05-03T15:16:55Z","fieldsType":"FieldsV1","fieldsV1":{"f:data":{".":{},"f:.dockerconfigjson":{}},"f:type":{}}}]},"data":{".dockerconfigjson":"{"auths":{"quay.io":{"username":"123","password":"123","auth":"MTIzOjEyMw=="}}}"},"type":"kubernetes.io/dockerconfigjson"},"oldObject":null,"dryRun":false,"options":{"kind":"CreateOptions","apiVersion":"meta.k8s.io/v1","fieldManager":"kubectl-create"}}}`,
			want:  []string{`quay.io:MTIzOjEyMw==`},
		},

		// False-positives
		{
			name: "registry.example.com",
			input: `1. Modify the runner's config.toml file as follows:

		[[runners]]
			environment = ["DOCKER_AUTH_CONFIG={\"auths\":{\"registry.example.com:5000\":{\"auth\":\"bXlfdXNlcm5hbWU6bXlfcGFzc3dvcmQ=\"}}}"]
			`,
		},
		{
			name: "",
			input: `sudo gitlab-runner register -n \
   --url https://gitlab.contoso.cn:8443/ \
   --registration-token ****** \
   --docker-extra-hosts "gitlab.contoso.cn:10.202.101.22" \
   --tag-list "golang-test" \
   --executor docker \
   --description "229 contoso golang test" \
   --docker-image "docker:19.03.1" \
   --docker-privileged \
   --env "DOCKER_AUTH_CONFIG={\"auths\": {\"registry.contoso123.cn:5000\": {\"auth\": \"******\"},\"registry.contoso.com.cn\": {\"auth\": \"******\"}}}" \
   --custom_build_dir-enabled=true  `,
		},
		// TODO: There's currently no solution to detect/ignore environment variables or placeholders.
		//	{
		//		name: "variables",
		//		input: `analyze_reports:
		//stage: post
		//image: registry.gitlab.com/detecttechnologies/software/webapps/t-pulse/web/tpulse-msa/tpulse-msa-cicd:production
		//variables:
		//  DOCKER_AUTH_CONFIG: '{"auths":{"registry.gitlab.com":{"username":"${CI_CD_API_USER}","password":"${CI_CD_API_TOKEN}"}}}'`,
		//	},

		{
			name: "empty registry",
			input: `The command outputs the following:
* A non-bootable configuration ISO ( agentconfig.noarch.iso)
* 'auth' directory: contains kubeconfig and kubeadmin-password

Note: for disconnected environments, specify a dummy pull-secret in install-config.yaml (e.g. '{"auths":{"":{"auth":"dXNlcjpwYXNz"}}}').`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

func Test_ParseAuth(t *testing.T) {
	tests := map[dockerAuth]string{
		// Only auth
		dockerAuth{
			Auth: "Ym9iOnMzY3IzdHBAc3N3MHJkIQ==",
		}: "bob:s3cr3tp@ssw0rd!",
		// Auth with colon
		dockerAuth{
			Auth: "OTM5MDQ5YjQtNTllMS00YzlhLWJlYzgtMjAyZTAxZjc2MWFlOjZCLkpFOmZPT2hvLTI3P244TlYybDZqQS9UdjBMd1hm",
		}: "939049b4-59e1-4c9a-bec8-202e01f761ae:6B.JE:fOOho-27?n8NV2l6jA/Tv0LwXf",
		// Only username + password
		dockerAuth{
			Username: "my_username",
			Password: "my_password",
		}: "my_username:my_password",
		// Auth and username+password
		dockerAuth{
			Auth:     "bXlfdXNlcm5hbWU6bXlfcGFzc3dvcmQ==",
			Username: "my_username",
			Password: "my_password",
		}: "my_username:my_password",
		// Kubernetes public test credentials
		// https://github.com/kubernetes/autoscaler/blob/f22b40eab867cbc52bdb15dc8768962e21d22837/vertical-pod-autoscaler/e2e/vendor/k8s.io/kubernetes/test/e2e/common/node/runtime.go#L283C1-L290C2
		dockerAuth{
			Auth: `X2pzb25fa2V5OnsKICAidHlwZSI6ICJzZXJ2aWNlX2FjY291bnQiLAogICJwcm9qZWN0X2lkIjogImF1dGhlbnRpY2F0ZWQtaW1hZ2UtcHVsbGluZyIsCiAgInByaXZhdGVfa2V5X2lkIjogImI5ZjJhNjY0YWE5YjIwNDg0Y2MxNTg2MDYzZmVmZGExOTIyNGFjM2IiLAogICJwcml2YXR
lX2tleSI6ICItLS0tLUJFR0lOIFBSSVZBVEUgS0VZLS0tLS1cbk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQzdTSG5LVEVFaVlMamZcbkpmQVBHbUozd3JCY2VJNTBKS0xxS21GWE5RL3REWGJRK2g5YVl4aldJTDhEeDBKZTc0bVovS01uV2dYRjVLWlNcbm9BNktuSU85Yi9SY1NlV2V
pSXRSekkzL1lYVitPNkNjcmpKSXl4anFWam5mVzJpM3NhMzd0OUE5VEZkbGZycm5cbjR6UkpiOWl4eU1YNGJMdHFGR3ZCMDNOSWl0QTNzVlo1ODhrb1FBZmgzSmhhQmVnTWorWjRSYko0aGVpQlFUMDNcbnZVbzViRWFQZVQ5RE16bHdzZWFQV2dydDZOME9VRGNBRTl4bGNJek11MjUzUG4vSzgySFpydEx4akd2UkhNVXhcbng0Zjh
wSnhmQ3h4QlN3Z1NORit3OWpkbXR2b0wwRmE3ZGducFJlODZWRDY2ejNZenJqNHlLRXRqc2hLZHl5VWRcbkl5cVhoN1JSQWdNQkFBRUNnZ0VBT3pzZHdaeENVVlFUeEFka2wvSTVTRFVidi9NazRwaWZxYjJEa2FnbmhFcG9cbjFJajJsNGlWMTByOS9uenJnY2p5VlBBd3pZWk1JeDFBZVF0RDdoUzRHWmFweXZKWUc3NkZpWFpQUm9
DVlB6b3VcbmZyOGRDaWFwbDV0enJDOWx2QXNHd29DTTdJWVRjZmNWdDdjRTEyRDNRS3NGNlo3QjJ6ZmdLS251WVBmK0NFNlRcbmNNMHkwaCtYRS9kMERvSERoVy96YU1yWEhqOFRvd2V1eXRrYmJzNGYvOUZqOVBuU2dET1lQd2xhbFZUcitGUWFcbkpSd1ZqVmxYcEZBUW14M0Jyd25rWnQzQ2lXV2lGM2QrSGk5RXRVYnRWclcxYjZ
nK1JRT0licWFtcis4YlJuZFhcbjZWZ3FCQWtKWjhSVnlkeFVQMGQxMUdqdU9QRHhCbkhCbmM0UW9rSXJFUUtCZ1FEMUNlaWN1ZGhXdGc0K2dTeGJcbnplanh0VjFONDFtZHVjQnpvMmp5b1dHbzNQVDh3ckJPL3lRRTM0cU9WSi9pZCs4SThoWjRvSWh1K0pBMDBzNmdcblRuSXErdi9kL1RFalk4MW5rWmlDa21SUFdiWHhhWXR4UjI
xS1BYckxOTlFKS2ttOHRkeVh5UHFsOE1veUdmQ1dcbjJ2aVBKS05iNkhabnY5Q3lqZEo5ZzJMRG5RS0JnUUREcVN2eURtaGViOTIzSW96NGxlZ01SK205Z2xYVWdTS2dcbkVzZlllbVJmbU5XQitDN3ZhSXlVUm1ZNU55TXhmQlZXc3dXRldLYXhjK0krYnFzZmx6elZZdFpwMThNR2pzTURcbmZlZWZBWDZCWk1zVXQ3Qmw3WjlWSjg
1bnRFZHFBQ0xwWitaLzN0SVJWdWdDV1pRMWhrbmxHa0dUMDI0SkVFKytcbk55SDFnM2QzUlFLQmdRQ1J2MXdKWkkwbVBsRklva0tGTkh1YTBUcDNLb1JTU1hzTURTVk9NK2xIckcxWHJtRjZcbkMwNGNTKzQ0N0dMUkxHOFVUaEpKbTRxckh0Ti9aK2dZOTYvMm1xYjRIakpORDM3TVhKQnZFYTN5ZUxTOHEvK1JcbjJGOU1LamRRaU5
LWnhQcG84VzhOSlREWTVOa1BaZGh4a2pzSHdVNGRTNjZwMVRESUU0MGd0TFpaRFFLQmdGaldcbktyblFpTnEzOS9iNm5QOFJNVGJDUUFKbmR3anhTUU5kQTVmcW1rQTlhRk9HbCtqamsxQ1BWa0tNSWxLSmdEYkpcbk9heDl2OUc2Ui9NSTFIR1hmV3QxWU56VnRocjRIdHNyQTB0U3BsbWhwZ05XRTZWejZuQURqdGZQSnMyZUdqdlh
cbmpQUnArdjhjY21MK3dTZzhQTGprM3ZsN2VlNXJsWWxNQndNdUdjUHhBb0dBZWRueGJXMVJMbVZubEFpSEx1L0xcbmxtZkF3RFdtRWlJMFVnK1BMbm9Pdk81dFE1ZDRXMS94RU44bFA0cWtzcGtmZk1Rbk5oNFNZR0VlQlQzMlpxQ1RcbkpSZ2YwWGpveXZ2dXA5eFhqTWtYcnBZL3ljMXpmcVRaQzBNTzkvMVVjMWJSR2RaMmR5M2x
SNU5XYXA3T1h5Zk9cblBQcE5Gb1BUWGd2M3FDcW5sTEhyR3pNPVxuLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLVxuIiwKICAiY2xpZW50X2VtYWlsIjogImltYWdlLXB1bGxpbmdAYXV0aGVudGljYXRlZC1pbWFnZS1wdWxsaW5nLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAiY2xpZW50X2lkIjogIjExMzc5NzkxNDUzMDA
3MzI3ODcxMiIsCiAgImF1dGhfdXJpIjogImh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi9hdXRoIiwKICAidG9rZW5fdXJpIjogImh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi90b2tlbiIsCiAgImF1dGhfcHJvdmlkZXJfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9vYXV0aDIvdjEvY2VydHMiLAogICJjbGllbnRfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9yb2JvdC92MS9tZXRhZGF0YS94NTA5L2ltYWdlLXB1bGxpbmclNDBhdXRoZW50aWNhdGVkLWltYWdlLXB1bGxpbmcuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iCn0=`,
		}: "_json_key:{\n  \"type\": \"service_account\",\n  \"project_id\": \"authenticated-image-pulling\",\n  \"private_key_id\": \"b9f2a664aa9b20484cc1586063fefda19224ac3b\",\n  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7SHnKTEEiYLjf\\nJfAPGmJ3wrBceI50JKLqKmFXNQ/tDXbQ+h9aYxjWIL8Dx0Je74mZ/KMnWgXF5KZS\\noA6KnIO9b/RcSeWeiItRzI3/YXV+O6CcrjJIyxjqVjnfW2i3sa37t9A9TFdlfrrn\\n4zRJb9ixyMX4bLtqFGvB03NIitA3sVZ588koQAfh3JhaBegMj+Z4RbJ4heiBQT03\\nvUo5bEaPeT9DMzlwseaPWgrt6N0OUDcAE9xlcIzMu253Pn/K82HZrtLxjGvRHMUx\\nx4f8pJxfCxxBSwgSNF+w9jdmtvoL0Fa7dgnpRe86VD66z3Yzrj4yKEtjshKdyyUd\\nIyqXh7RRAgMBAAECggEAOzsdwZxCUVQTxAdkl/I5SDUbv/Mk4pifqb2DkagnhEpo\\n1Ij2l4iV10r9/nzrgcjyVPAwzYZMIx1AeQtD7hS4GZapyvJYG76FiXZPRoCVPzou\\nfr8dCiapl5tzrC9lvAsGwoCM7IYTcfcVt7cE12D3QKsF6Z7B2zfgKKnuYPf+CE6T\\ncM0y0h+XE/d0DoHDhW/zaMrXHj8Toweuytkbbs4f/9Fj9PnSgDOYPwlalVTr+FQa\\nJRwVjVlXpFAQmx3BrwnkZt3CiWWiF3d+Hi9EtUbtVrW1b6g+RQOIbqamr+8bRndX\\n6VgqBAkJZ8RVydxUP0d11GjuOPDxBnHBnc4QokIrEQKBgQD1CeicudhWtg4+gSxb\\nzejxtV1N41mducBzo2jyoWGo3PT8wrBO/yQE34qOVJ/id+8I8hZ4oIhu+JA00s6g\\nTnIq+v/d/TEjY81nkZiCkmRPWbXxaYtxR21KPXrLNNQJKkm8tdyXyPql8MoyGfCW\\n2viPJKNb6HZnv9CyjdJ9g2LDnQKBgQDDqSvyDmheb923Ioz4legMR+m9glXUgSKg\\nEsfYemRfmNWB+C7vaIyURmY5NyMxfBVWswWFWKaxc+I+bqsflzzVYtZp18MGjsMD\\nfeefAX6BZMsUt7Bl7Z9VJ85ntEdqACLpZ+Z/3tIRVugCWZQ1hknlGkGT024JEE++\\nNyH1g3d3RQKBgQCRv1wJZI0mPlFIokKFNHua0Tp3KoRSSXsMDSVOM+lHrG1XrmF6\\nC04cS+447GLRLG8UThJJm4qrHtN/Z+gY96/2mqb4HjJND37MXJBvEa3yeLS8q/+R\\n2F9MKjdQiNKZxPpo8W8NJTDY5NkPZdhxkjsHwU4dS66p1TDIE40gtLZZDQKBgFjW\\nKrnQiNq39/b6nP8RMTbCQAJndwjxSQNdA5fqmkA9aFOGl+jjk1CPVkKMIlKJgDbJ\\nOax9v9G6R/MI1HGXfWt1YNzVthr4HtsrA0tSplmhpgNWE6Vz6nADjtfPJs2eGjvX\\njPRp+v8ccmL+wSg8PLjk3vl7ee5rlYlMBwMuGcPxAoGAednxbW1RLmVnlAiHLu/L\\nlmfAwDWmEiI0Ug+PLnoOvO5tQ5d4W1/xEN8lP4qkspkffMQnNh4SYGEeBT32ZqCT\\nJRgf0Xjoyvvup9xXjMkXrpY/yc1zfqTZC0MO9/1Uc1bRGdZ2dy3lR5NWap7OXyfO\\nPPpNFoPTXgv3qCqnlLHrGzM=\\n-----END PRIVATE KEY-----\\n\",\n  \"client_email\": \"image-pulling@authenticated-image-pulling.iam.gserviceaccount.com\",\n  \"client_id\": \"113797914530073278712\",\n  \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n  \"token_uri\": \"https://accounts.google.com/o/oauth2/token\",\n  \"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",\n  \"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/image-pulling%40authenticated-image-pulling.iam.gserviceaccount.com\"\n}",

		// Errors
		// Auth isn't `username:password` format.
		dockerAuth{
			Auth: "dGhpc2lzYXN0cmluZ3dpdGhvdXRhbnljb2xvbg==",
		}: "",
		// Invalid base64
		dockerAuth{
			Auth: "asda42asd214ASDKqwwq==",
		}: "",
	}

	ctx := context.Background()
	for input, expected := range tests {
		username, password, encoded := parseBasicAuth(ctx.Logger(), input)

		if expected == "" {
			if encoded != "" {
				t.Errorf("expected an error, got: username=%s, password=%s, encoded=%s", username, password, encoded)
			}
			continue
		}

		if diff := cmp.Diff(expected, username+":"+password); diff != "" {
			t.Errorf("%s diff: (-want +got)\n%s", input, diff)
		}
	}
}

func Test_ParseAuthenticateHeader(t *testing.T) {
	tests := map[string]map[string]string{
		`Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`: {
			"scheme":  "Bearer",
			"realm":   "https://auth.docker.io/token",
			"service": "registry.docker.io",
		},
		`Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:user/image:pull"`: {
			"scheme":  "Bearer",
			"realm":   "https://ghcr.io/token",
			"service": "ghcr.io",
			"scope":   "repository:user/image:pull",
		},
		`Bearer realm="https://artifactory.example.com:443/artifactory/api/docker/docker-repo/v2/token",service="artifactory.example.com:443"`: {
			"scheme":  "Bearer",
			"realm":   "https://artifactory.example.com:443/artifactory/api/docker/docker-repo/v2/token",
			"service": "artifactory.example.com:443",
		},
	}

	for input, expected := range tests {
		actual, err := parseAuthenticateHeader(input)
		if err != nil {
			t.Errorf("failed to parse www-authenticate header: %v", err)
		}

		if diff := cmp.Diff(expected, actual); diff != "" {
			t.Errorf("%s diff: (-want +got)\n%s", input, diff)
		}
	}
}
