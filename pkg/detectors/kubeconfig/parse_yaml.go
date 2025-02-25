package kubeconfig

import (
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"
)

var (
	// Attempts to match the "clusters" object.
	// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/#NamedCluster
	clustersObjectPat = regexp.MustCompile(`clusters:[\s\S]+?(?:(?:kind|apiVersion|preferences|contexts|users|current-context):|\z)`)
	clusterEntryPat   = regexp.MustCompile(`-[ \t]*cluster:(?:.|\s)+?server:[ \t]*['"]?(https?://[\w.\-:\/]+)['"]?(?:.|\s)+?name:[ \t]*['"]?([\w\-:]+)['"]?`)
	// Attempts to match the "contexts" object.
	// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/#NamedContext
	contextsObjectPat = regexp.MustCompile(`contexts:[[\s\S]+(?:(?:kind|apiVersion|preferences|clusters|users|current-context):|\z)`)
	contextEntryPat   = regexp.MustCompile(`-[ \t]*context:(?:.|\s)+?cluster:[ \t]*['"]?([\w\-:]+)['"]?(?:.|\s)+?user:[ \t]*['"]?([\w\-:\/]+)['"]?(?:.|\s)+?name:[ \t]*['"]?([\w\-:\/]+)['"]?`)
	// Attempts to match the "users" object.
	// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/#NamedAuthInfo
	usersObjectPat  = regexp.MustCompile(`users:[\s\S]+?(?:(?:kind|apiVersion|preferences|contexts|clusters|current-context):|\z)`)
	userEntryPat    = regexp.MustCompile(`-[ \t]*name:[ \t]*['"]?([\w\-:\/]+)['"]?(?:.|\s)+?(client-key(?:-data)?|password|token):[ \t]*['"]?([\w.\-\/]+={0,2})['"]?(?:\s|$)`)
	userUsernamePat = func(password string) *regexp.Regexp {
		return regexp.MustCompile(fmt.Sprintf(`['"]?password['"]?:[ \t]*['"]?%s['"]?(?:.|\s)+username:[ \t]*['"]?([\w.\-\/]+={0,2})['"]?(?:\s|$)`, password))
	}
)

func parseYaml(data string) ([]cluster, []error) {
	// Parse `clusters` object.
	clustersObject := clustersObjectPat.FindString(data)
	if clustersObject == "" {
		return nil, []error{noClustersObjectError}
	}
	clusterEntries := clusterEntryPat.FindAllStringSubmatch(clustersObject, -1)
	if len(clusterEntries) == 0 {
		return nil, []error{noClusterEntriesError}
	}

	urlByClusterName := make(map[string]string)
	for _, m := range clusterEntries {
		server := m[1]
		name := m[2]
		urlByClusterName[name] = server
	}

	// Parse `contexts` object.
	contextsObject := contextsObjectPat.FindString(data)
	if contextsObject == "" {
		return nil, []error{noContextsObjectError}
	}
	contextEntries := contextEntryPat.FindAllStringSubmatch(contextsObject, -1)
	if len(contextEntries) == 0 {
		return nil, []error{noContextsError}
	}

	// A cluster can be associated with multiple users.
	// A cluster/user can have multiple entries for different namespaces.
	usersByCluster := make(map[string]map[string]struct{})
	for _, m := range contextEntries {
		cluster := m[1]
		user := m[2]
		if _, ok := usersByCluster[cluster]; !ok {
			// If the outer key doesn't exist, initialize the nested map
			usersByCluster[cluster] = make(map[string]struct{})
		}

		usersByCluster[cluster][user] = struct{}{}
	}

	// Parse `users` object.
	usersObject := usersObjectPat.FindString(data)
	if usersObject == "" {
		return nil, []error{noUsersObjectError}
	}
	userEntries := userEntryPat.FindAllStringSubmatch(usersObject, -1)
	if len(userEntries) == 0 {
		return nil, []error{noUsersError}
	}

	authByUser := make(map[string]clusterAuth)
	parseErrors := make([]error, 0)
	for _, m := range userEntries {
		var (
			name      = m[1]
			authType  = m[2]
			authValue = m[3]

			auth clusterAuth
		)

		switch authType {
		case "client-key":
			// Path to a file; we can't use this.
			auth = clusterAuth{Type: externalAuth}
		case "client-key-data":
			auth = clusterAuth{
				Type:      clientKeyAuth,
				ClientKey: authValue,
			}

			// The base64 decoder can provide mangled data.
			// Ensure that the certificate value starts with `-----BEGIN`, base64-encoded.
			if !strings.HasPrefix(authValue, "LS0tLS1CRUdJTi") {
				continue
			}
		case "password":
			auth = clusterAuth{
				Type:     passwordAuth,
				Password: authValue,
			}
		case "token":
			auth = clusterAuth{
				Type:  tokenAuth,
				Token: authValue,
			}
		case "auth-provider", "exec":
			// Authentication can use a custom `auth-provider`, `exec` command, or other extension.
			auth = clusterAuth{Type: externalAuth}
		default:
			parseErrors = append(parseErrors, fmt.Errorf("user '%s' has unknown auth type: %s", name, authType))
			auth = clusterAuth{Type: unknownAuth}
		}

		authByUser[name] = auth
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

			// If the auth is password, there is a distinct `username` field that we need.
			if auth.Type == passwordAuth {
				usernamePat := userUsernamePat(auth.Password)
				matches := usernamePat.FindStringSubmatch(data)
				if len(matches) == 0 {
					// This could indicate that the file was truncated by the chunker.
					err := fmt.Errorf("user '%s@%s' auth info has a `password` but no `username`", user, clusterName)
					parseErrors = append(parseErrors, err)
					continue
				}

				auth.Username = matches[1]
			}

			cluster.Auth = auth
			clusters = append(clusters, cluster)
		}
	}

	return clusters, parseErrors
}
