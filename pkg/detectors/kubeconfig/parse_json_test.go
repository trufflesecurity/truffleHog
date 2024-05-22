package kubeconfig

import (
	"errors"
	"testing"
)

// Happy path: valid, parseable auth.
func Test_Json_ValidAuth(t *testing.T) {
	tests := []testCase{
		{
			name: "ClientKey auth",
			input: `{"k8s":{"name":"kubernetes","config":{
  "apiVersion": "v1",
  "clusters": [
    {
      "cluster": {
        "certificate-authority-data": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN5RENDQWJDZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRFNU1USXdNekE1TURFME1Gb1hEVEk1TVRFek1EQTVNREUwTUZvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTU9XCk1ub3FNRzA3YWxxOUFEVXc3bkN6ZXJiUzRRdzhwWWlkVkZYZHRrQ3JKK0xJR21QcXJ1Y1VkL0o2aGpzREhrRVkKbGplT1M2cGxUWXNmSVlWL1JRQmQ2WGZQcVc5OTgrSXdhYmFoTzdlQmx0MVgyanJiWlBUVm4yeXZwcGRCTUp0dgp5OHo3MkYrK1RES0V5VnJoVXF6UUJCTC95bEJDeWFPNnpYbHovYlhXWm1IWXRBTjVNQ3R4ekRGQWhycWl5WGY4Cjk0MkxhbWZmQ1N0VFN2SXo2OE81dVpZSS82RzFOaW9jaTZvMDVibHIzWmY1Q2xnTERkcUV1ckw2a3hTOHY4a3kKMTdIWndSS2NqcDZoMzZ2cUdURlQ2Zm9IdjFzNjd4c3g0U3FacEpEbmVOVDVDZWJRMWdLTytXUVl5dmVoNkpnSgp4My9QRkthR0RKMlRCd3lBNWNzQ0F3RUFBYU1qTUNFd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFFTlFTQWxtekVac1g4RU82aFFZRmpDTjdLNGwKSDZvd3l2aisvdDBlelkzS0NjUEJMaTJlbFMyeklBVjNic2pDUndSc1h1ekMrTnhmcXhvVkRyekdmOE5pVWFZMgorZFZ5UlNLbXdCYzFmRjdoNTQrT0hmaS9DZVE4RlR3OE9aWkdPaDBBdXYyM1M4THh6SGEwMEZ1YWpLTDFpWTUwCllTVllZU1MrblBBMlM0TTFkTTNXSGdTMmZPdWV2b0djTm14MXdVRENMdnV2NkN0YjhVU0xFbDJCOWpPb1RFVFgKZUZtaEFGNXVmMjJuRWlubHdKeUVzTjY2OXBPaGdiQXZXbDFxdkxhbDlHTjBWR3NYNFhaTVpHSkt4YkVTUmhLNwpxekE5cFlZbnlwRngxd3phN1g2aUdCeWVGeTZDS1FGS3J4dTV0VUhHZGQ5cmhUcU9Td0JoWVVXeEFoMD0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
        "server": "https://apiserver.node1:6443"
      },
      "name": "kubernetes-m"
    },
    {
      "cluster": {
        "certificate-authority-data": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN5RENDQWJDZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRFNU1USXdOREF6TlRBd09Gb1hEVEk1TVRJd01UQXpOVEF3T0Zvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTFlzCkxBbFZnZE9qWlY4cmIwS1Ewd1ZPTUd0d2tkb29sZnlUTHo0VVM2ZFhzbTREcEYwbk4xU3pJRFVoVE1tWEh0bDEKTEg2YU9KNGdtYmNTOUdtNFVIQnBxYm81YmM5SHplcjh5bEErTTJGKzJGYjVoVHBUYnJKOXJmMWlVN21VNndjQwpjTUFJRzhCNEpiaVUraEdNQSs2bTJPckZ3Ympsck5TcmRsV21kUzNxNDZ1TEtHTzlyVnRYdVEvR0VKanIvQWs4CmFJYmcyNnFGWVdrVzR5WWlsVWlsS3IzZVpzS3R2ZHBkbEVNcTA3SXpnalRrYVVRMEdpR1RYRW1wWFBCcnRYTW4KQUh3bCtCQVF4OTdlVW8wZ3BpNm44WDh2T0lseEs5ZEx5Si9KVnNkOUlzVkh4bzY5TFNabVNrMnNqVFNWZlJhMQpaZ3RHRXJLK0ZuTWlNeUdPNVdVQ0F3RUFBYU1qTUNFd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFGaW91ZlRnYjE4S0lmT2k3bXNWWmoyakVzUDEKUnp3Z0ZFQ3Voa3lKZC9tWWxNMlI2dUVOb0d4OWpJUi9GeUxvaDB2dmxwZm1iUUdDck1NOTh0L28vYkNTNHRVaApsbTVWemNEclA4VGlDRFR0VWY2NG5kM1QvZENrR1MxZzBPTjNqTUZJaU9vQmhyaW1KbnRHWkI3WHhDbmFIZUpoCi9vMHdsWUhtcnFVbGZ2R1ZpQm9LU3poZnY4cVA4ZUxxbUN3MyszUnIrTGdpQjhaNFkyRkZ0ekxoY0YvZ0MzRy8KY081UUtjWkZDbjhoWlhEZDBBUE1pREJLOE50QWNOYU5IV3grR1RkZ2t4Z1drN2lJQUgrTkVBT0hrRzEyZUhHSApDN0tZcmRIWWxyZnNhRWw4Vnh6U3NYZ0NnQU9UT3IxWXg3WDVodkVnZlRCSTRGbHl0V09xT1pxRHB0TT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
        "server": "https://apiserver.kube.local:6443"
      },
      "name": "kubernetes-s"
    }
  ],
  "contexts": [
    {
      "context": {
        "cluster": "kubernetes-m",
        "namespace": "default",
        "user": "kubernetes-admin-m"
      },
      "name": "kubernetes-admin@kubernetes-m"
    },
    {
      "context": {
        "cluster": "kubernetes-s",
        "namespace": "kong",
        "user": "kubernetes-admin-s"
      },
      "name": "kubernetes-admin@kubernetes-s"
    }
  ],
  "current-context": "kubernetes-admin@kubernetes-s",
  "kind": "Config",
  "preferences": {},
  "users": [
    {
      "name": "kubernetes-admin-m",
      "user": {
        "client-certificate-data": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM4akNDQWRxZ0F3SUJBZ0lJRDlxcnZIUVNCNVF3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB4T1RFeU1ETXdPVEF4TkRCYUZ3MHlNREV5TURJd09UQXhOREphTURReApGekFWQmdOVkJBb1REbk41YzNSbGJUcHRZWE4wWlhKek1Sa3dGd1lEVlFRREV4QnJkV0psY201bGRHVnpMV0ZrCmJXbHVNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXZBYXFialV3Qkg5cytQWngKMDFlc1ZRdlU1eHlnWWJEdWxhdG9qSVB1TFF6bFY3OEdqcE9YUDlVcW9wQTUwbVJsMTE4WWh5bDdIVTRwMURkaApKbUtDcWU5SWprdTJPamxQTDAzSW9Hc1c0WHNCVUNuMnQ0Uit4alA0QThUOUJrUS94czVLUElJblRyeXRKaXNTCjVPQklvMDNBeEswdlJsbUJPQ3l4dzRrVTZUMCtDZEZzenFTYUxkM3IydzQzOGFSeGkvdkRPNHVnbWFpQnZ1S0wKYk8yOHl1WEFsM1pVTGxnQUxwcHFBUXZTWTluektsbXpYaExlU3hIODRLcjBVNFFiQjlVRHdpdmJGVDRaN2R5TApmdWVmWEJUeXcxRWYvWlhzNlhJQkVMTlMwZVhsZXpUTmsrb1R5N0NieDUyU2dldjF1R0pkVG1KSEVZaGdiazZ2CnFHSlFMd0lEQVFBQm95Y3dKVEFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUgKQXdJd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFIL1ByTWcxaGtkdUJZWEp6elkwb0VPSW05SVZFcFJWNjNYMApPVnNQUHk4OFNtRDQwMUhmV1NrREREdEVqY2kxajFFK1I0ZFRtRktJWFBxbDdxbFVWeWNmMEJucjUxRGVDUDR0CjNYUmI3Y2kxcGhyNVh2bHZ1Tkh6RHdnSWEyOWVPbkxKZ2xYeDNyNXI2RjNKSkIwekxzUXhSTHUwRFk4V3FvVU8KeHExdXdYR0hKdXZhcVVBc1F0UnV2eEF2RzVLRGlwQTZtUjFxZTZWbjAwSTZpMTc3RFBpbWhXZ1dmVHpZNkJkNgo1Zi8rRzQyMVg2dGFiQnp5WGFQb1NGTURpcDRaTkc3ZFQwYlRlNWhkZ0pIVmlzVUd3WkxXR0NKbndlUTR3cGNqCi9uYlNkUzdiNE9xZXpBbnVCa2p4M21nbTE0cjB6eFhvMGNkWjU3eUxzRzhaa2NPSWRXMD0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
        "client-key-data": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdkFhcWJqVXdCSDlzK1BaeDAxZXNWUXZVNXh5Z1liRHVsYXRvaklQdUxRemxWNzhHCmpwT1hQOVVxb3BBNTBtUmwxMThZaHlsN0hVNHAxRGRoSm1LQ3FlOUlqa3UyT2psUEwwM0lvR3NXNFhzQlVDbjIKdDRSK3hqUDRBOFQ5QmtRL3hzNUtQSUluVHJ5dEppc1M1T0JJbzAzQXhLMHZSbG1CT0N5eHc0a1U2VDArQ2RGcwp6cVNhTGQzcjJ3NDM4YVJ4aS92RE80dWdtYWlCdnVLTGJPMjh5dVhBbDNaVUxsZ0FMcHBxQVF2U1k5bnpLbG16ClhoTGVTeEg4NEtyMFU0UWJCOVVEd2l2YkZUNFo3ZHlMZnVlZlhCVHl3MUVmL1pYczZYSUJFTE5TMGVYbGV6VE4KaytvVHk3Q2J4NTJTZ2V2MXVHSmRUbUpIRVloZ2JrNnZxR0pRTHdJREFRQUJBb0lCQUFEMng4am8zT1lwQVJZRgpyVyszODFvOFJVc3FDbWgxejhOVXJhU0t5SjNTZ3hxQUVEaUs2U3VhbkMxWkwvSzBNUkY1bTFhV0Q5dUdteEJMCmVHUUovVUdCeUkxeU5lejJma0Z2MUtkOTVSQWk0VTdYNkR2b29mM0NKbk5lZnkyWkMvcW85Qmg3VWxoRS8xNUMKdWtZU0lFMDJDTmI1VEZUQUFMbVpBUkJQazV2ZWdrQ3Y0dFY1Y29rVk01N2pJOU5GS2g0cW1DSVRDazhjZWlDNQp3bDRITjlrK3p6TlpUcDB4ZXZVUkNDWkRiZHhEcjgwZkh5L0dnS1pIcmQ0cXo5NG5GT2liVVl5dTlXZ0IwdzhrCjh6OFBDV2hDQnRvWmtVMTdFOXZlSzN5Vi82ak1BQkNQcm96aWNXVld6cXlSbW9COEQyTXlpcXFjTHRNSDdEbk0KY1FJdkhBRUNnWUVBeUphUVNRLy92N01LaDJjdE1GdTB1Nytkbm5vcWl0bnY5akZaOHMvdTVuck5wSC8yWFVwTAppcE0wTW9rYUwrS054R3dBR1FSaGNkZ2wzdE9iZTRlbnloUzZZV2FGUzRIbzI4dTdUQTZDSy9hN0xkbGZML0RFCnZCSlBMeDNSTWdWZHRUVDJ6VDVvRmVQR3pwQ0ZNa1JpL3d5Zy83aDRiRnB1VTUwN2JRbmE4NkVDZ1lFQTcvZTQKWEp6bjVMNFMyejMzV0FqOTVBVzYzaWFVbWpSMGphOGt0MEJiNGlaek10UVF3UzBlb1dHQXVBRm9aY2xDL1YybApqd0FHYnVaN1Bpc0V4MHlwT001Y0NmbTlXWUdpSlFPbGhZY0pxc3BhY29nYUF3K1RONzAxbVAzeExlZzRTMFp2CmNLb1ZsblB5N3piaU9oUDJ4bm1HQ213Zm5seWd0aXYrMWZQRnNjOENnWUVBcmxyaGxBQ0tKNUZ6UjNzUnRvVWcKTmtvNnNiUXpJbnFKc0kvNVJhd2tWc2JMMVg4OUlKNGh4NVJvdkx5YnZKL0s1citSM2kwR25yUnBScVRjODZWWQozYmppd1NNaUhoNFAwRzNvb2hYQ1pJQ1U5eWVKSzl5MnhWdU01TUdnUTBDUzBaMzJJVFZydUF0RGxlM2RPWEprCk1wcEJuOFl6TnN2c05sWG5mOElmUmNFQ2dZQUxGbEw2VkhXU2FBWFBBMm51TTF3bnNPd1ZYNHIySlA1Tm5ZNEEKdVlTRlNtbUFLN1FxZUw4MWpaKzQ0TGZHSENwd01tZDMxL1IwSTBvR2NVNWpOdk9Lb0Y0NFI4V3I0UVZ3MkY1SgpjUmZOUUZRMWZueFZMOThKY0VDTnRRM3pwUXNVejBoTzJFenZDcVJxMFFwYXpKbFdTajhiTkN1eDBXM0xmUFRsClJjSVltUUtCZ0QzMUt2dDl6emltaGJ6UXVkM3NGUDlOcE40bERTdEM4bnhuTlpVVDV0K3I3WldYZHBmcy9yWEYKZHlWd3NYSlpSb0V2RThLQkFFdDFJN3JQbVR6ajVWVkFuVm9kQXlodE5BZE9VbFJlbFd6UWJBbzRjRGFJNXB2bgpBUjltZmxQZ2V6c25ZVGJIdHREanhpWVJ3bDRwcGVaWWRpNkEwajlKdWNjaHhvOGhmSG0xCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=="
      }
    },
    {
      "name": "kubernetes-admin-s",
      "user": {
        "client-certificate-data": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM4akNDQWRxZ0F3SUJBZ0lJUnRMa2FEQVlRSDR3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB4T1RFeU1EUXdNelV3TURoYUZ3MHlNREV5TURNd016VXdNVEphTURReApGekFWQmdOVkJBb1REbk41YzNSbGJUcHRZWE4wWlhKek1Sa3dGd1lEVlFRREV4QnJkV0psY201bGRHVnpMV0ZrCmJXbHVNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQTZmMGtsMm13RDd5d0haa24KT3IyRlFGVE9wOVVMREpXNUkyVHRlNmJkTjViNWJzQnhZRlV4dWk3WlFTaUtneW5pN0tsSHh4MHhDc3BrcUtaSQp2bWJqN25OdWlEOGRQRmFyVXdISnJzYmU1OHNnbVRKK2JuWjdHRDFRbFp6bUw4Q0VvaDluYjY3UWJqN0xLK0pUCnQwbVI2d3hyZ1RLMnllY2xoOStWUW1WZGxFeHQ0dEJrWHFYMGo2anU0M3N6ejBjZUZ4ZTQ2TkdxcksrNXFXZGEKc1Uwdm8vK3VwN3hFSFVVdjIxQVNhc083MDg3K09aRU54bm9ETnZwWFRxRXF0SUdhL0VnaE5UV2dab0ZoNU1vKwpzTGlLbEZlK09OTUtiVER0Y2JESE5HOWliVjFsZWt0a2xXbjc4RGxjYlZWU2FxMHIzSkJZRUVhMVBERVB5a2V3CkE0Z2NQd0lEQVFBQm95Y3dKVEFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUgKQXdJd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFDVFpja2VUWWJlNmhGZVdMcjYyaXQxajNQMXE4QThHSUpncQpjQ1pGaG5ycXVUMXp6S3hISk80TktHaGZXNjZ3N0g5dlhyU1R1TEtnYUdBMGZDa1RPSnZJa3ZRV0Q1VWNtVUtHCjI3UEI4NVRQUWt3QWh3QkRNQmJhazNSVktFaGRZNXpLcUJ3UWVER3ZmUGsrSkFGQjA2VXIxak5DNXROVzRKc1gKQ25XNDQ2SVpkZm00eGRwR2FDWHFJTDM1T0N4dzJjbnNmeVdSVjlIMWJFcEtobkxsSU1KQ2w2QWhwbUdRMFVWcQpUZlhlV0FCRjBOYlRsTU54K0RBb0Z2Vkwwck4za2NQUEdtMnAxU0N1R3dhRDRuSGNoVE1UYUY4aUkyMm9CcXNDClhsRDJpQTNidG5ISWxGeUIzZWhmUHlZOUxYU0Z6Yk5oQm9QWjFGdDh2a080d1BzYlVzYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
        "client-key-data": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBNmYwa2wybXdEN3l3SFprbk9yMkZRRlRPcDlVTERKVzVJMlR0ZTZiZE41YjVic0J4CllGVXh1aTdaUVNpS2d5bmk3S2xIeHgweENzcGtxS1pJdm1iajduTnVpRDhkUEZhclV3SEpyc2JlNThzZ21USisKYm5aN0dEMVFsWnptTDhDRW9oOW5iNjdRYmo3TEsrSlR0MG1SNnd4cmdUSzJ5ZWNsaDkrVlFtVmRsRXh0NHRCawpYcVgwajZqdTQzc3p6MGNlRnhlNDZOR3FySys1cVdkYXNVMHZvLyt1cDd4RUhVVXYyMUFTYXNPNzA4NytPWkVOCnhub0ROdnBYVHFFcXRJR2EvRWdoTlRXZ1pvRmg1TW8rc0xpS2xGZStPTk1LYlREdGNiREhORzlpYlYxbGVrdGsKbFduNzhEbGNiVlZTYXEwcjNKQllFRWExUERFUHlrZXdBNGdjUHdJREFRQUJBb0lCQUZiVHI4TmIzWkJKWlZUbQpZdzlDQ25OUHhRdTBXNUJFOHRsMmQwVitLdktZM0dCRG13NnpMbXUzUExrWUVTWVE0ZnNONmV1eUltT3RyT0tFCktkUTFtL2o4N3BReVQyZjNoVVdkRVRrQTVQQkFpUTB3Rm9ocEFNNkMyaWRhZkhSVnpTSFg0MnNuQklNVVhCSWgKdnd6eGlPc2V4Ym5BbHVHZkcyY3JDVmtGQWsrbnd5amJVN01ORGVobXk2a3cyZWhUUXVqZ0hGamhMdjJRbnpKawoydjh3Z0w1VWh3alRSdVdqd3FzYy95bWFxTnl1SDRERnF5ZGxhRWpGVjF2Zm5TZUNCbFJ5T3ByQWxGdFI5RWJFCm9aMThoZ1RlditJN04wNm1IU05kSlFuSDduaTF2Z1gwR2lYeE4wNGVuY3JWbGFDTm1ueldpcVdoVVhUVld2UGMKSEhWSk9URUNnWUVBOE5IaFdqMWxQUnV6YllxbTdRbWNsR3hQYzF3S1A5a3pvVm0vUTd2ODdYUkZWc29vN2p6SApEK2NzRFFBYnRTeHR4WVRkMGRjVFVvVzI4TkNQMGp3VjZHSERrQ1FVcVhkMzBkSnlYYjc1L0U4ZEJhU2tTcGtQCitzbjBKSGZyMHBPWWRscGxCZlh2SjNQZ2gxT0loSFkyVW5ZbDhSbzNTaUpOL0R3L21MZGVicmNDZ1lFQStMMEgKeXVtc2xhcjI0alFvdmZielcvMTRQcmZaVGJqb3BqamE2S0VxL3B0QmUxWkM3SzhhMHFBaFdDNmZ5Z2JXSStLUwo2dlBEaWh3cWxtTUx2cnlKa3dTMHJ4UXdxMXBOT1BIV2NCQ1RaQWh3bVhqMW1yNkxZQ09QWGM3YUVXMmRmai9lClNMU3Y5Mmp5Y0k0WWQwYTN4R3BrK2M2NDNkU2ZmSVBISXpzTXRya0NnWUVBd1VneWpyTG9KbnV0THlZeGc5NUwKQmZWSWIxWllBNWJZa1kvdXF2YWVzaGEzOEVpaFFWVVdqL1VDcmd5QU1KRlFLVS9TbVREK0dTV3BCdTdkLythcAp6ckZvdksrNHhhdFZSOXFZWUJWL25yb0FtUjdqbmR2cnIyV1h4ZzFhQU5EbGRWaG43TGpQRWVNM09tWVpFL2VzCjhkSlI4WWtSQnpjeFVGa3EwZSthbzFFQ2dZRUF6TEpiY0Z4ZklBaERCaUtnaUx4cXg0QlBiV1hGR2RZYTkzZ0EKaHNMamJBWCtuRzUvd3VIVGRCUTlmS0ZaOUZzdDdQZ3ZxZFVUVFZ3aW5BSkVqeUgvSVpNVTBxUU43V1h4K1BQawpZZkx5S0xkZFdwK1ZsMVJKeE1OZTMzYzBOSFY5ejREbC8vVmFmb1BLU0dCWHVBamxnR21DVWFZU3N0T2dzRXFPCkhlc2hhbGtDZ1lCRWNCNmJCMUlONXJQRGdYejJZcnpuYlZkWHRxbkM1dWx2Qk1zR1oyTWQzbExJUFN6Y2FudXEKeXo3dW5mTjFGeWoxMFJ4RFY4K0tXQlZFTEwyZ1VhbWVSLzd3RlZJN1dTaXkyczVHVDFmRTg1cjBaTW5pZmlRSApjKy9tbWFvbnFSMzNVcXBJb0hyNUJha0FlamRQTkRtZ1Fkb1ZTQ2EzbDU0OWtlMEZrNUxUVlE9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="
      }
    }
  ]
}}}`,
			want: []cluster{
				{
					Server: "https://apiserver.node1:6443",
					User:   "kubernetes-admin-m",
					Auth: clusterAuth{
						Type:      clientKeyAuth,
						ClientKey: "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdkFhcWJqVXdCSDlzK1BaeDAxZXNWUXZVNXh5Z1liRHVsYXRvaklQdUxRemxWNzhHCmpwT1hQOVVxb3BBNTBtUmwxMThZaHlsN0hVNHAxRGRoSm1LQ3FlOUlqa3UyT2psUEwwM0lvR3NXNFhzQlVDbjIKdDRSK3hqUDRBOFQ5QmtRL3hzNUtQSUluVHJ5dEppc1M1T0JJbzAzQXhLMHZSbG1CT0N5eHc0a1U2VDArQ2RGcwp6cVNhTGQzcjJ3NDM4YVJ4aS92RE80dWdtYWlCdnVLTGJPMjh5dVhBbDNaVUxsZ0FMcHBxQVF2U1k5bnpLbG16ClhoTGVTeEg4NEtyMFU0UWJCOVVEd2l2YkZUNFo3ZHlMZnVlZlhCVHl3MUVmL1pYczZYSUJFTE5TMGVYbGV6VE4KaytvVHk3Q2J4NTJTZ2V2MXVHSmRUbUpIRVloZ2JrNnZxR0pRTHdJREFRQUJBb0lCQUFEMng4am8zT1lwQVJZRgpyVyszODFvOFJVc3FDbWgxejhOVXJhU0t5SjNTZ3hxQUVEaUs2U3VhbkMxWkwvSzBNUkY1bTFhV0Q5dUdteEJMCmVHUUovVUdCeUkxeU5lejJma0Z2MUtkOTVSQWk0VTdYNkR2b29mM0NKbk5lZnkyWkMvcW85Qmg3VWxoRS8xNUMKdWtZU0lFMDJDTmI1VEZUQUFMbVpBUkJQazV2ZWdrQ3Y0dFY1Y29rVk01N2pJOU5GS2g0cW1DSVRDazhjZWlDNQp3bDRITjlrK3p6TlpUcDB4ZXZVUkNDWkRiZHhEcjgwZkh5L0dnS1pIcmQ0cXo5NG5GT2liVVl5dTlXZ0IwdzhrCjh6OFBDV2hDQnRvWmtVMTdFOXZlSzN5Vi82ak1BQkNQcm96aWNXVld6cXlSbW9COEQyTXlpcXFjTHRNSDdEbk0KY1FJdkhBRUNnWUVBeUphUVNRLy92N01LaDJjdE1GdTB1Nytkbm5vcWl0bnY5akZaOHMvdTVuck5wSC8yWFVwTAppcE0wTW9rYUwrS054R3dBR1FSaGNkZ2wzdE9iZTRlbnloUzZZV2FGUzRIbzI4dTdUQTZDSy9hN0xkbGZML0RFCnZCSlBMeDNSTWdWZHRUVDJ6VDVvRmVQR3pwQ0ZNa1JpL3d5Zy83aDRiRnB1VTUwN2JRbmE4NkVDZ1lFQTcvZTQKWEp6bjVMNFMyejMzV0FqOTVBVzYzaWFVbWpSMGphOGt0MEJiNGlaek10UVF3UzBlb1dHQXVBRm9aY2xDL1YybApqd0FHYnVaN1Bpc0V4MHlwT001Y0NmbTlXWUdpSlFPbGhZY0pxc3BhY29nYUF3K1RONzAxbVAzeExlZzRTMFp2CmNLb1ZsblB5N3piaU9oUDJ4bm1HQ213Zm5seWd0aXYrMWZQRnNjOENnWUVBcmxyaGxBQ0tKNUZ6UjNzUnRvVWcKTmtvNnNiUXpJbnFKc0kvNVJhd2tWc2JMMVg4OUlKNGh4NVJvdkx5YnZKL0s1citSM2kwR25yUnBScVRjODZWWQozYmppd1NNaUhoNFAwRzNvb2hYQ1pJQ1U5eWVKSzl5MnhWdU01TUdnUTBDUzBaMzJJVFZydUF0RGxlM2RPWEprCk1wcEJuOFl6TnN2c05sWG5mOElmUmNFQ2dZQUxGbEw2VkhXU2FBWFBBMm51TTF3bnNPd1ZYNHIySlA1Tm5ZNEEKdVlTRlNtbUFLN1FxZUw4MWpaKzQ0TGZHSENwd01tZDMxL1IwSTBvR2NVNWpOdk9Lb0Y0NFI4V3I0UVZ3MkY1SgpjUmZOUUZRMWZueFZMOThKY0VDTnRRM3pwUXNVejBoTzJFenZDcVJxMFFwYXpKbFdTajhiTkN1eDBXM0xmUFRsClJjSVltUUtCZ0QzMUt2dDl6emltaGJ6UXVkM3NGUDlOcE40bERTdEM4bnhuTlpVVDV0K3I3WldYZHBmcy9yWEYKZHlWd3NYSlpSb0V2RThLQkFFdDFJN3JQbVR6ajVWVkFuVm9kQXlodE5BZE9VbFJlbFd6UWJBbzRjRGFJNXB2bgpBUjltZmxQZ2V6c25ZVGJIdHREanhpWVJ3bDRwcGVaWWRpNkEwajlKdWNjaHhvOGhmSG0xCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==",
					},
				},
				{
					Server: "https://apiserver.kube.local:6443",
					User:   "kubernetes-admin-s",
					Auth: clusterAuth{
						Type:      clientKeyAuth,
						ClientKey: "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBNmYwa2wybXdEN3l3SFprbk9yMkZRRlRPcDlVTERKVzVJMlR0ZTZiZE41YjVic0J4CllGVXh1aTdaUVNpS2d5bmk3S2xIeHgweENzcGtxS1pJdm1iajduTnVpRDhkUEZhclV3SEpyc2JlNThzZ21USisKYm5aN0dEMVFsWnptTDhDRW9oOW5iNjdRYmo3TEsrSlR0MG1SNnd4cmdUSzJ5ZWNsaDkrVlFtVmRsRXh0NHRCawpYcVgwajZqdTQzc3p6MGNlRnhlNDZOR3FySys1cVdkYXNVMHZvLyt1cDd4RUhVVXYyMUFTYXNPNzA4NytPWkVOCnhub0ROdnBYVHFFcXRJR2EvRWdoTlRXZ1pvRmg1TW8rc0xpS2xGZStPTk1LYlREdGNiREhORzlpYlYxbGVrdGsKbFduNzhEbGNiVlZTYXEwcjNKQllFRWExUERFUHlrZXdBNGdjUHdJREFRQUJBb0lCQUZiVHI4TmIzWkJKWlZUbQpZdzlDQ25OUHhRdTBXNUJFOHRsMmQwVitLdktZM0dCRG13NnpMbXUzUExrWUVTWVE0ZnNONmV1eUltT3RyT0tFCktkUTFtL2o4N3BReVQyZjNoVVdkRVRrQTVQQkFpUTB3Rm9ocEFNNkMyaWRhZkhSVnpTSFg0MnNuQklNVVhCSWgKdnd6eGlPc2V4Ym5BbHVHZkcyY3JDVmtGQWsrbnd5amJVN01ORGVobXk2a3cyZWhUUXVqZ0hGamhMdjJRbnpKawoydjh3Z0w1VWh3alRSdVdqd3FzYy95bWFxTnl1SDRERnF5ZGxhRWpGVjF2Zm5TZUNCbFJ5T3ByQWxGdFI5RWJFCm9aMThoZ1RlditJN04wNm1IU05kSlFuSDduaTF2Z1gwR2lYeE4wNGVuY3JWbGFDTm1ueldpcVdoVVhUVld2UGMKSEhWSk9URUNnWUVBOE5IaFdqMWxQUnV6YllxbTdRbWNsR3hQYzF3S1A5a3pvVm0vUTd2ODdYUkZWc29vN2p6SApEK2NzRFFBYnRTeHR4WVRkMGRjVFVvVzI4TkNQMGp3VjZHSERrQ1FVcVhkMzBkSnlYYjc1L0U4ZEJhU2tTcGtQCitzbjBKSGZyMHBPWWRscGxCZlh2SjNQZ2gxT0loSFkyVW5ZbDhSbzNTaUpOL0R3L21MZGVicmNDZ1lFQStMMEgKeXVtc2xhcjI0alFvdmZielcvMTRQcmZaVGJqb3BqamE2S0VxL3B0QmUxWkM3SzhhMHFBaFdDNmZ5Z2JXSStLUwo2dlBEaWh3cWxtTUx2cnlKa3dTMHJ4UXdxMXBOT1BIV2NCQ1RaQWh3bVhqMW1yNkxZQ09QWGM3YUVXMmRmai9lClNMU3Y5Mmp5Y0k0WWQwYTN4R3BrK2M2NDNkU2ZmSVBISXpzTXRya0NnWUVBd1VneWpyTG9KbnV0THlZeGc5NUwKQmZWSWIxWllBNWJZa1kvdXF2YWVzaGEzOEVpaFFWVVdqL1VDcmd5QU1KRlFLVS9TbVREK0dTV3BCdTdkLythcAp6ckZvdksrNHhhdFZSOXFZWUJWL25yb0FtUjdqbmR2cnIyV1h4ZzFhQU5EbGRWaG43TGpQRWVNM09tWVpFL2VzCjhkSlI4WWtSQnpjeFVGa3EwZSthbzFFQ2dZRUF6TEpiY0Z4ZklBaERCaUtnaUx4cXg0QlBiV1hGR2RZYTkzZ0EKaHNMamJBWCtuRzUvd3VIVGRCUTlmS0ZaOUZzdDdQZ3ZxZFVUVFZ3aW5BSkVqeUgvSVpNVTBxUU43V1h4K1BQawpZZkx5S0xkZFdwK1ZsMVJKeE1OZTMzYzBOSFY5ejREbC8vVmFmb1BLU0dCWHVBamxnR21DVWFZU3N0T2dzRXFPCkhlc2hhbGtDZ1lCRWNCNmJCMUlONXJQRGdYejJZcnpuYlZkWHRxbkM1dWx2Qk1zR1oyTWQzbExJUFN6Y2FudXEKeXo3dW5mTjFGeWoxMFJ4RFY4K0tXQlZFTEwyZ1VhbWVSLzd3RlZJN1dTaXkyczVHVDFmRTg1cjBaTW5pZmlRSApjKy9tbWFvbnFSMzNVcXBJb0hyNUJha0FlamRQTkRtZ1Fkb1ZTQ2EzbDU0OWtlMEZrNUxUVlE9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=",
					},
				},
			},
		},
		{
			name: "Token auth",
			input: `{
    "apiVersion": "v1",
    "clusters": [
        {
            "cluster": {
                "server": "https://k8s.corp.net:6443"
            },
            "name": "default"
        }
    ],
    "contexts": [
        {
            "context": {
                "cluster": "default",
                "namespace": "corpbot",
                "user": "corpbot"
            },
            "name": "default"
        }
    ],
    "current-context": "default",
    "kind": "Config",
    "users": [
        {
            "name": "corpbot",
            "user": {
                "token": "yI4ehbwWp0OU6dO0QsT6GTHxQhehC2HEyMEDgxxTmYlV2CynEWBQOTquNn3MXrlT"
            }
        }
    ]
}`,
			want: []cluster{
				{
					Server: "https://k8s.corp.net:6443",
					User:   "corpbot",
					Auth: clusterAuth{
						Type:  tokenAuth,
						Token: "yI4ehbwWp0OU6dO0QsT6GTHxQhehC2HEyMEDgxxTmYlV2CynEWBQOTquNn3MXrlT",
					},
				},
			},
		},
		{
			name: "Password auth",
			input: `{
  "apiVersion": "v1",
  "kind": "Config",
  "preferences": {},
  "clusters": [
    {
      "cluster": {
        "certificate-authority-data": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJWakNCL3FBREFnRUNBZ0VBTUFvR0NDcUdTTTQ5QkFNQ01DTXhJVEFmQmdOVkJBTU1HR3N6Y3kxelpYSjIKWlhJdFkyRkFNVFU1T0RJNE5qZ3pNekFlRncweU1EQTRNalF4TmpNek5UTmFGdzB6TURBNE1qSXhOak16TlROYQpNQ014SVRBZkJnTlZCQU1NR0dzemN5MXpaWEoyWlhJdFkyRkFNVFU1T0RJNE5qZ3pNekJaTUJNR0J5cUdTTTQ5CkFnRUdDQ3FHU000OUF3RUhBMElBQkp3ZTF2UXR0T1F6c2xaVTNUQkhSWlQzS293UWdHdnY1TnYvZko5NTRpSkkKbG5nbHVyZktWQk9nbDM2bFp2UGJGdzVKTTFpSWYzaEVmVTZxU3crNThSR2pJekFoTUE0R0ExVWREd0VCL3dRRQpBd0lDcERBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUVSMG81dm82K1pXCkVkaE1GYXpVWk9CTnhkVk14N0dRTTY1MCsyWFBzZTBJQWlBVkJBWmZUdE94SkN0Q2lZQnp6alhzM29MWWhyZzYKcFVhQ0o3Nyt0VFpycUE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
        "server": "https://127.0.0.1:6443"
      },
      "name": "default"
    },
   	{
      "cluster": {
        "certificate-authority": "./ca.crt",
        "server": "https://192.168.99.100:8443"
      },
      "name": "minikube"
    }
  ],
  "contexts": [
    {
      "context": {
        "cluster": "default",
        "user": "default"
      },
      "name": "default"
    },
    {
      "context": {
        "cluster": "minikube",
        "user": "minikube"
      },
      "name": "minikube"
    }
  ],
  "current-context": "default",
  "users": [
    {
      "name": "default",
      "user": {
        "password": "f976df38c1bc4ed617413adef8844217",
        "username": "admin"
      }
    },
	{
		"name":"minikube",
		"user": {
			"client-certificate":"/tmp/vm-state-kube/xchg/secrets/cluster-admin.pem",
			"client-key":"/tmp/vm-state-kube/xchg/secrets/cluster-admin-key.pem"
		}
	}
  ]
}
`,
			want: []cluster{
				{
					Server: "https://127.0.0.1:6443",
					User:   "default",
					Auth: clusterAuth{
						Type:     passwordAuth,
						Username: "admin",
						Password: "f976df38c1bc4ed617413adef8844217",
					},
				},
			},
		},
	}
	runTest(t, parseJson, tests)
}

func Test_Json_DifferentOrder(t *testing.T) {
	tests := []testCase{
		{
			name: "clusters>users>contexts",
			input: `{
  "preferences": {},
  "clusters": [
    {
      "cluster": {
        "server": "https://127.0.0.1:6443"
      },
      "name": "a"
    }
  ],
  "users": [
    {
      "name": "a",
      "user": {
        "token": "a"
      }
    }
  ],
  "contexts": [
    {
      "context": {
        "cluster": "a",
        "user": "a"
      },
      "name": "a"
    }
  ],
  "current-context": "a"
}`,
			want: []cluster{
				{Server: "https://127.0.0.1:6443", User: "a", Auth: clusterAuth{Type: tokenAuth, Token: "a"}},
			},
		},
		{
			name: "users>contexts>clusters",
			input: `{
  "apiVersion": "v1",
  "users": [
    {
      "name": "a",
      "user": {
        "token": "a"
      }
    }
  ],
  "contexts": [
    {
      "context": {
        "cluster": "a",
        "user": "a"
      },
      "name": "a"
    }
  ],
  "current-context": "a",
  "clusters": [
    {
      "cluster": {
        "server": "https://127.0.0.1:6443"
      },
      "name": "a"
    }
  ],
  "kind": "Config",
  "preferences": {}
}`,
			want: []cluster{
				{Server: "https://127.0.0.1:6443", User: "a", Auth: clusterAuth{Type: tokenAuth, Token: "a"}},
			},
		},
	}

	runTest(t, parseJson, tests)
}

// Auth is provided by an external source (file, extension).
func Test_Json_ExternalAuth(t *testing.T) {
	tests := []testCase{
		// Certificate is stored in a file.
		{
			name: "client-certificate",
			input: `{
  "apiVersion": "v1",
  "kind": "Config",
  "preferences": {},
  "clusters": [
   	{
      "cluster": {
        "certificate-authority": "./ca.crt",
        "server": "https://192.168.99.100:8443"
      },
      "name": "minikube"
    }
  ],
  "contexts": [
    {
      "context": {
        "cluster": "minikube",
        "user": "minikube"
      },
      "name": "minikube"
    }
  ],
  "current-context": "default",
  "users": [
	{
		"name":"minikube",
		"user": {
			"client-certificate":"/tmp/vm-state-kube/xchg/secrets/cluster-admin.pem",
			"client-key":"/tmp/vm-state-kube/xchg/secrets/cluster-admin-key.pem"
		}
	}
  ]
}`,
		},
		// Token is stored in a file.
		// TODO: Find an example of this.
		{
			name:  "tokenFile",
			input: ``,
			skip:  true,
		},
		// Custom plugin to provide credentials.
		{
			name: "auth-provider",
			input: `{
	"apiVersion": "v1",
	"clusters": [
		{
			"cluster": {
				"certificate-authority-data": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUV5VENDQXJHZ0F3SUJBZ0lRTDZFWHZDU3ovcTQ0Um51RlFtYnJPekFOQmdrcWhraUc5dzBCQVFzRkFEQU4KTVFzd0NRWURWUVFERXdKallUQWdGdzB5TVRBeU1qSXhOelExTVRKYUdBOHlNRFV4TURJeE5URTNORFV4TWxvdwpEVEVMTUFrR0ExVUVBeE1DWTJFd2dnSWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUNEd0F3Z2dJS0FvSUNBUUNjCnpkNFRvRERwZHdMYWhyb250TGhwRkpsS0lVdTZBVGw1SnN3VnU4ek5pTUVsVWxoTjZmVmdUY2hXMVNDM3NaTHoKWitpSnNUL3l4TWJQN0I3M3F3UC92Wkh2YUNhMldPSDZ5UmRWbDQ3UmhFbU8wbHA5SnlHVGNzd0JXVy9MNnVLeApTVWRoSmI1WExoOEZHVzZDVUZpU0cxNHVCcUM2bzRKMDRRWmt6YWo4djA3YnBYeWhXUWg3Z3FWTU9NRWEwZzdlCm9GbS85QndoNnIvZThzcXc3SkZ4WTFVT25VcVl6WnhCR1NXQ3N5aTZhVDc1SnlOY2ZaUXV6S1A4VnpKNGZFK0cKRmJ1SSt2Q2VqWUMyTnFweU0vV1VaM3BJSXR0dm5RcVk2ekxtSUlKcSt5dk9yb005KytaNjV2NVl4Zzh0aG9LawpmdktjOXl2TDNHdjB4OUhEZ2JXSlhjcG1pR1h2ZEoxaXNSZUw1WFI5b0NWeTJxcTVKV1dOQWFhU1M2OUhjbXpPCjVyYTRRa0F3d0xQaWJkTXJOK0F2bDlwTmhGOHRjYm1DakZlOHIvbStrTEJ4cHYvdXVDL25vK3hEbnA0MGsrckcKQ1NyRkJNTWJwbStCamExSnMwR0trZ2lUcERBVlZyUmt5MjJQdjd4N1k0TjdoUk42R0MyZGtTU0hpV21sTmJESwpNZWFTek1ucVc1bTlhUTcrL2s1cGk0d01WdWZQNUJEM3dJVXh5N0lEdi9RaXVNVXkrNjNYdkVYYlZTeVEyOXVCCkpLY3JVT2s5dDUzd3hENXZUaFpNZGJYR0pYOTVzSXk3bzR3ajNnMWJKS0FvbjlGUEVGYUFvaFFGUWNxY0VyV2wKTGpEQXY2UjBMM3ZJNWlyMEhwdWIvdGRVS3YrOThCRnBzcjRXWXJYVTZ3SURBUUFCb3lNd0lUQU9CZ05WSFE4QgpBZjhFQkFNQ0FxUXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FnRUFYTXZJCkVjTjdxNHFyUTVQYU54dzljVXozdDZUNFpvUVFPcHp5YUVHM3IxK1k2OWVJbzNRenpycENDRmI5OXZFZnVsaGwKeVlnQUw5cmQ5Q0tsMld0TDh6dTkzNmNtS0ZHMXFTczFBTW9ZcC9ZM2RDMTVUUlBxT3UxUmZTa0JOWU8rOE1WcQo4OE5jMTJPQWVZU1BqNUpVdUVTTW9KWWg2Tm1KMC92bitxRmorQUVwcWkzR0p2SG5rRjFYM3JnanlhUGMrZG1TClJxdVZqc3U5K3pSdGdQTzZDd3p3bGtMcWNyQnU1eUZKWGxpeVZZc1FNNVBveXQ4a1drOXE2UGp3dnQ3MUdDbEIKb3M0TU5ETk1Hb3d5bWNwVTUwcDZxMGx4VE80eERzUUV1c1ZtOUIxOVRFZGFVVXQyUW5jUWwrOVFOZXFydVFXNwpyNVdKdWNYUFZDSXEvWXIyK29YdWpqa0w0eU1RMWNickRtcmpYaDI1b04vN0Uvd1VlTVpXL2lXbmZsRXZrc2xXCkk4VHp6S21HbWdhU0h6WitkVmRpRDBWU29DeXc4bnd4M3BaVEdEY0E2YWhVdmU2TTRUOGkveTRVMlY0MFFRc20KczdaVHJoNlJiU2JGWlFTMldxOHduZ09QKzkxVE4yMXp1VUxRTldhem1qWDE2MitIZDNZZTJMYlR4S3YrQzAwYgpCb29ldGRyWTBCK2tqaTIxSFF4aGkrTTRoN3J3ZXhmckFOcWpmSkVhMzBTandZSnREcGdQZ3VmZTdtTU5LZFAyCnV0cmYyMkgwNmNEZi9QTmo4ZjJGOEdKRGFRZFJZTnZYUFlTMVpFOVhkY3Y0d3BVRGF2Tk45akliQW9mdTF3NGwKOFZ6T1VYQXl2N25hOENtQlE0aXVGR081V1BxcGlDVi9lbmJkRE8wPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
				"server": "https://193.0.1.10"
			},
			"name": "aks-engine-workshop-cluster-6033eda0"
		}
	],
	"contexts": [
		{
			"context": {
				"cluster": "aks-engine-workshop-cluster-6033eda0",
				"user": "aks-engine-workshop-cluster-6033eda0-admin"
			},
			"name": "aks-engine-workshop-cluster-6033eda0"
		}
	],
	"current-context": "aks-engine-workshop-cluster-6033eda0",
	"kind": "Config",
	"users": [
		{
			"name": "aks-engine-workshop-cluster-6033eda0-admin",
			"user": {"auth-provider":{"name":"azure","config":{"environment":"AzurePublicCloud","tenant-id":"3851f269-b22b-4de6-97d6-aa9fe60fe301","apiserver-id":"3adf37ca-d914-43e9-9b24-8c081e0b3a08","client-id":"70dba699-0fba-4c1d-805e-213acea0a63e"}}}
		}
	]
}`,
		},
		// Custom command to provide credentials.
		// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/#ExecConfig
		{
			name: "exec",
			input: `{
  "apiVersion": "v1",
  "kind": "Config",
  "current-context": "terraform",
  "clusters": [
    {
      "name": "terraform",
      "cluster": {
        "insecure-skip-tls-verify": true,
        "server": "<CLUSTER_ENDPOINT>"
      }
    }
  ],
  "users": [
    {
      "name": "terraform",
      "user": {
        "exec": {
          "apiVersion": "client.authentication.k8s.io/v1beta1",
          "command": "aws-iam-authenticator",
          "args": [
            "token",
            "-i",
            "<CLUSTER_NAME>",
            "-r",
            "<AWS_IAM_ROLE_ADMIN_ARN>"
          ]
        }
      }
    }
  ],
  "contexts": [
    {
      "name": "terraform",
      "context": {
        "cluster": "terraform",
        "user": "terraform"
      }
    }
  ]
}`,
		},
	}
	runTest(t, parseJson, tests)
}

func Test_Json_UnknownAuth(t *testing.T) {
	tests := []testCase{
		{
			name: "Missing auth info",
			input: `{
    "apiVersion":"v1",
    "clusters":
    [
        {
            "cluster":
            {
                "certificate-authority":"/tmp/vm-state-kube/xchg/secrets/ca.pem",
                "server":"https://127.0.0.1:5443"
            },
            "name":"kubenix"
        },
        {
            "cluster":
            {
                "certificate-authority":"/tmp/vm-state-kube/xchg/secrets/ca.pem",
                "server":"https://127.0.0.1:5443"
            },
            "name":"kubenix2"
        }
    ],
    "contexts":
    [
        {
            "context":
            {
                "cluster":"kubenix",
                "user":"cluster-admin"
            },
            "current-context":"kubenix"
        },
        {
            "context":
            {
                "cluster":"kubenix2",
                "user":"cluster-admin2"
            },
            "current-context":"kubenix2"
        }
    ],
    "kind":"Config",
    "users":
    [
        {
            "name": "cluster-admin",
            "user": {
                "token": "yI4ehbwWp0OU6dO0QsT6GTHxQhehC2HEyMEDgxxTmYlV2CynEWBQOTquNn3MXrlT"
            }
        }
    ]
}`,
			want: []cluster{
				{
					Server: "https://127.0.0.1:5443",
					User:   "cluster-admin",
					Auth: clusterAuth{
						Type:  tokenAuth,
						Token: "yI4ehbwWp0OU6dO0QsT6GTHxQhehC2HEyMEDgxxTmYlV2CynEWBQOTquNn3MXrlT",
					},
				},
			},
			wantErrs: []error{errors.New("user 'cluster-admin2@kubenix2' has no associated auth info")},
		},
	}
	runTest(t, parseJson, tests)
}

func Test_Json_Unparseable(t *testing.T) {
	tests := []testCase{
		{
			name: "Empty config",
			input: `{
  "apiVersion": "v1",
  "kind": "Config",
  "preferences": {},
  "clusters": [],
  "contexts": [],
  "current-context": "default",
  "users": [ ]
}`,
			wantErrs: []error{noClusterEntriesError},
		},

		// False positives
		{
			name: "Invalid JSON",
			input: `{
        "apiVersion": "v1",
        "clusters": [
            {
                "cluster": {
                    "insecure-skip-tls-verify": True,
                    "server": apiServer
                },
                "name": "sreworks_cluster"
            }
        ],
        "contexts": [
            {
                "context": {
                    "cluster": "sreworks_cluster",
                    "user": "sreworks_admin"
                },
                "name": "t"
            }
        ],
        "current-context": "t",
        "kind": "Config",
        "preferences": {},
        "users": [
            {
                "name": "sreworks_admin",
                "user": {
                    "token": token,
                }
            }
        ]
    }`,
			wantErrs: []error{},
		},
		{
			name:     "Placeholder values",
			input:    `{ "apiVersion": "v1", "clusters": [ { "cluster": { "certificate-authority-data": "xxxxxx==", "server": "https://xxxxx.com" }, "name": "cls-xxxxx" } ], "contexts": [ { "context": { "cluster": "cls-xxxxx", "user": "100014xxxxx" }, "name": "cls-a44yhcxxxxxxxxxx" } ], "current-context": "cls-a4xxxx-context-default", "kind": "Config", "preferences": {}, "users": [ { "name": "100014xxxxx", "user": { "client-certificate-data": "xxxxxx", "client-key-data": "xxxxxx" } } ]} */`,
			wantErrs: []error{errors.New("user '100014xxxxx@cls-xxxxx' has no associated auth info")},
		},
	}

	runTest(t, parseJson, tests)
}
