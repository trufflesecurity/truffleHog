package kubeconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"
)

var (
	jsonpat   = regexp.MustCompile(`\\*"(?:clusters|contexts|users)\\*"[ \t]*:\s*?\[`)
	configPat = regexp.MustCompile(`\{(?:(?:[^{]|\s)*\\*"(?:kind|apiVersion|preferences|clusters|users|contexts|current-context)\\*"[ \t]*:(?:.|\s)*,?)}`)
)

// parseJsonConfig attempts to parse the KubeConfig format.
// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/
func parseJson(data string) ([]cluster, []error) {
	configStr := configPat.FindString(data)
	if configStr == "" {
		return nil, []error{noUsersObjectError}
	}

	// It's impossible to match start/end brackets with regex.
	// However, `json.NewDecoder` will ignore any extraneous data.
	var conf config
	if err := json.NewDecoder(strings.NewReader(configStr)).Decode(&conf); err != nil {
		// Ignore invalid JSON.
		var jsonErr *json.SyntaxError
		if errors.As(err, &jsonErr) {
			return nil, nil
		}
		return nil, []error{err}
	}
	// Ignore empty configs.
	// Could mean the data was JSON, but didn't match the config.
	if len(conf.Clusters) == 0 && len(conf.Contexts) == 0 && len(conf.AuthInfos) == 0 {
		return nil, nil
	}

	// Parse clusters.
	urlByClusterName := make(map[string]string)
	for _, c := range conf.Clusters {
		urlByClusterName[c.Name] = c.Cluster.Server
	}

	// Parse contexts
	// A cluster can be associated with multiple users.
	// A cluster/user can have multiple entries for different namespaces.
	usersByCluster := make(map[string]map[string]struct{})
	for _, c := range conf.Contexts {
		cluster := c.Context.Cluster
		if _, ok := usersByCluster[cluster]; !ok {
			// If the outer key doesn't exist, initialize the nested map
			usersByCluster[cluster] = make(map[string]struct{})
		}

		usersByCluster[cluster][c.Context.User] = struct{}{}
	}

	// Parse users
	// A cluster can be associated with multiple users.
	// A cluster/user can have multiple entries for different namespaces.
	authByUser := make(map[string]clusterAuth)
	parseErrors := make([]error, 0)
	for _, info := range conf.AuthInfos {
		var (
			auth clusterAuth
			u    = info.User
		)

		switch {
		case u.ClientKeyData != "":
			auth = clusterAuth{
				Type:      clientKeyAuth,
				ClientKey: u.ClientKeyData,
			}

			// The base64 decoder can provide mangled data.
			// Ensure that the certificate value starts with `-----BEGIN`, base64-encoded.
			if !strings.HasPrefix(auth.ClientKey, "LS0tLS1CRUdJTi") {
				continue
			}
		case u.Password != "":
			auth = clusterAuth{
				Type:     passwordAuth,
				Username: u.Username,
				Password: u.Password,
			}
		case u.Token != "":
			auth = clusterAuth{
				Type:  tokenAuth,
				Token: u.Token,
			}
		case u.ClientKey != "", u.TokenFile != "", u.AuthProvider != nil, u.Exec != nil:
			// External
			auth = clusterAuth{Type: externalAuth}
		default:
			parseErrors = append(parseErrors, fmt.Errorf("user '%s' has unknown auth type", info.Name))
			auth = clusterAuth{Type: unknownAuth}
		}

		authByUser[info.Name] = auth
	}

	// Assemble the data.
	clusters := make([]cluster, 0)
	for clusterName, clusterUrl := range urlByClusterName {
		users, ok := usersByCluster[clusterName]
		if !ok {
			// This could indicate that the file was truncated by the chunker.
			err := fmt.Errorf("cluster '%s' has no associated users", clusterName)
			parseErrors = append(parseErrors, err)
			continue
		}

		for user := range users {
			cluster := cluster{
				Server: clusterUrl,
				User:   user,
			}

			auth, ok := authByUser[user]
			if !ok {
				// This could indicate that the file was truncated by the chunker.
				err := fmt.Errorf("user '%s@%s' has no associated auth info", user, clusterName)
				parseErrors = append(parseErrors, err)
				continue
			} else if auth.Type == unknownAuth || auth.Type == externalAuth {
				// Auth info was found for the user, but we can't use it for some reason.
				continue
			}

			cluster.Auth = auth
			clusters = append(clusters, cluster)
		}
	}

	if len(clusters) > 0 {
		return clusters, parseErrors
	} else {
		return nil, parseErrors
	}
}

type config struct {
	Clusters  []namedCluster  `json:"clusters"`
	Contexts  []namedContext  `json:"contexts"`
	AuthInfos []namedAuthInfo `json:"users"`
}

// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/#NamedCluster
// https://github.com/kubernetes/kubernetes/blob/4bb434501d9ee5edda6faf52a9d6d32a969ae183/staging/src/k8s.io/client-go/tools/clientcmd/api/v1/types.go#L163
type namedCluster struct {
	Name    string      `json:"name"`
	Cluster kubeCluster `json:"cluster"`
}

// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/#Cluster
// https://github.com/kubernetes/kubernetes/blob/4bb434501d9ee5edda6faf52a9d6d32a969ae183/staging/src/k8s.io/client-go/tools/clientcmd/api/types.go#L67
type kubeCluster struct {
	Server string `json:"server"`
}

// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/#NamedContext
// https://github.com/kubernetes/kubernetes/blob/4bb434501d9ee5edda6faf52a9d6d32a969ae183/staging/src/k8s.io/client-go/tools/clientcmd/api/v1/types.go#L171
type namedContext struct {
	Name    string         `json:"name"`
	Context clusterContext `json:"context"`
}

// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/#Context
// https://github.com/kubernetes/kubernetes/blob/4bb434501d9ee5edda6faf52a9d6d32a969ae183/staging/src/k8s.io/client-go/tools/clientcmd/api/types.go#L159
type clusterContext struct {
	Cluster string `json:"cluster"`
	User    string `json:"user"`
}

// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/#NamedAuthInfo
// https://github.com/kubernetes/kubernetes/blob/4bb434501d9ee5edda6faf52a9d6d32a969ae183/staging/src/k8s.io/client-go/tools/clientcmd/api/v1/types.go#L179
type namedAuthInfo struct {
	Name string   `json:"name"`
	User authInfo `json:"user"`
}

// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/#AuthInfo
// https://github.com/kubernetes/kubernetes/blob/4bb434501d9ee5edda6faf52a9d6d32a969ae183/staging/src/k8s.io/client-go/tools/clientcmd/api/types.go#L107
type authInfo struct {
	ClientCertificate     string              `json:"client-certificate"`
	ClientCertificateData string              `json:"client-certificate-data"`
	ClientKey             string              `json:"client-key"`
	ClientKeyData         string              `json:"client-key-data"`
	Token                 string              `json:"token"`
	TokenFile             string              `json:"tokenFile"`
	Username              string              `json:"username"`
	Password              string              `json:"password"`
	AuthProvider          *authProviderConfig `json:"auth-provider"`
	Exec                  *execConfig         `json:"exec,omitempty"`
}

// https://github.com/kubernetes/kubernetes/blob/fad52aedfcc14061cf20370be061789b4f3d97d9/staging/src/k8s.io/client-go/tools/clientcmd/api/v1/types.go#L195
type authProviderConfig struct {
	Name string `json:"name"`
}

// https://github.com/kubernetes/kubernetes/blob/fad52aedfcc14061cf20370be061789b4f3d97d9/staging/src/k8s.io/client-go/tools/clientcmd/api/v1/types.go#L205
type execConfig struct {
	Command string `json:"command"`
}
