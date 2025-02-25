package common

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

var caCerts = []string{
	// 	CN = ISRG Root X1
	// TODO: Expires Monday, June 4, 2035 at 4:04:38 AM Pacific
	`
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----	
`,
	// 	CN = ISRG Root X2
	// TODO: Expires September 17, 2040 at 9:00:00 AM Pacific Daylight Time
	`
-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----
`,
}

func PinnedCertPool() *x509.CertPool {
	trustedCerts := x509.NewCertPool()
	for _, cert := range caCerts {
		trustedCerts.AppendCertsFromPEM([]byte(strings.TrimSpace(cert)))
	}
	return trustedCerts
}

type FakeTransport struct {
	CreateResponse func(req *http.Request) (*http.Response, error)
}

func (t FakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.CreateResponse(req)
}

type CustomTransport struct {
	T http.RoundTripper
}

func UserAgent() string {
	if len(feature.UserAgentSuffix.Load()) > 0 {
		return "TruffleHog " + feature.UserAgentSuffix.Load()
	}
	return "TruffleHog"
}

func (t *CustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", UserAgent())
	return t.T.RoundTrip(req)
}

func NewCustomTransport(T http.RoundTripper) *CustomTransport {
	if T == nil {
		T = http.DefaultTransport
	}
	return &CustomTransport{T}
}

func ConstantResponseHttpClient(statusCode int, body string) *http.Client {
	return &http.Client{
		Timeout: DefaultResponseTimeout,
		Transport: FakeTransport{
			CreateResponse: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					Request:    req,
					Body:       io.NopCloser(strings.NewReader(body)),
					StatusCode: statusCode,
				}, nil
			},
		},
	}
}

// ClientOption configures how we set up the client.
type ClientOption func(*retryablehttp.Client)

// WithCheckRetry allows setting a custom CheckRetry policy.
func WithCheckRetry(cr retryablehttp.CheckRetry) ClientOption {
	return func(c *retryablehttp.Client) { c.CheckRetry = cr }
}

// WithBackoff allows setting a custom backoff policy.
func WithBackoff(b retryablehttp.Backoff) ClientOption {
	return func(c *retryablehttp.Client) { c.Backoff = b }
}

// WithTimeout allows setting a custom timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *retryablehttp.Client) { c.HTTPClient.Timeout = timeout }
}

// WithMaxRetries allows setting a custom maximum number of retries.
func WithMaxRetries(retries int) ClientOption {
	return func(c *retryablehttp.Client) { c.RetryMax = retries }
}

// WithRetryWaitMin allows setting a custom minimum retry wait.
func WithRetryWaitMin(wait time.Duration) ClientOption {
	return func(c *retryablehttp.Client) { c.RetryWaitMin = wait }
}

// WithRetryWaitMax allows setting a custom maximum retry wait.
func WithRetryWaitMax(wait time.Duration) ClientOption {
	return func(c *retryablehttp.Client) { c.RetryWaitMax = wait }
}

func PinnedRetryableHttpClient() *http.Client {
	httpClient := retryablehttp.NewClient()
	httpClient.Logger = nil
	httpClient.HTTPClient.Transport = NewCustomTransport(&http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: PinnedCertPool(),
		},
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	})
	return httpClient.StandardClient()
}

func RetryableHTTPClient(opts ...ClientOption) *http.Client {
	httpClient := retryablehttp.NewClient()
	httpClient.RetryMax = 3
	httpClient.Logger = nil
	httpClient.HTTPClient.Transport = NewCustomTransport(nil)

	for _, opt := range opts {
		opt(httpClient)
	}
	return httpClient.StandardClient()
}

func RetryableHTTPClientTimeout(timeOutSeconds int64, opts ...ClientOption) *http.Client {
	httpClient := retryablehttp.NewClient()
	httpClient.RetryMax = 3
	httpClient.Logger = nil
	httpClient.HTTPClient.Timeout = time.Duration(timeOutSeconds) * time.Second
	httpClient.HTTPClient.Transport = NewCustomTransport(nil)

	for _, opt := range opts {
		opt(httpClient)
	}
	return httpClient.StandardClient()
}

const DefaultResponseTimeout = 5 * time.Second

var saneTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   2 * time.Second,
		KeepAlive: 5 * time.Second,
	}).DialContext,
	MaxIdleConns:          5,
	IdleConnTimeout:       5 * time.Second,
	TLSHandshakeTimeout:   3 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

func SaneHttpClient() *http.Client {
	httpClient := &http.Client{}
	httpClient.Timeout = DefaultResponseTimeout
	httpClient.Transport = NewCustomTransport(saneTransport)
	return httpClient
}

// SaneHttpClientTimeOut adds a custom timeout for some scanners
func SaneHttpClientTimeOut(timeout time.Duration) *http.Client {
	httpClient := &http.Client{}
	httpClient.Timeout = timeout
	httpClient.Transport = NewCustomTransport(nil)
	return httpClient
}
