package kubeconfig

import (
	"errors"
)

type cluster struct {
	Server string
	User   string
	Auth   clusterAuth
}

func (c cluster) GetUser() string {
	if c.Auth.Type == passwordAuth {
		return c.Auth.Username
	}
	return c.User
}

type clusterAuth struct {
	Type      authType
	ClientKey string
	Username  string
	Password  string
	Token     string
}

type authType int

const (
	unknownAuth authType = iota
	externalAuth
	clientKeyAuth
	tokenAuth
	passwordAuth
)

func (t authType) String() string {
	return [...]string{
		"UnknownAuth",
		"ExternalAuth",
		"ClientKeyAuth",
		"TokenAuth",
		"PasswordAuth",
	}[t]
}

func (c *clusterAuth) GetValue() string {
	switch c.Type {
	case clientKeyAuth:
		return c.ClientKey
	case passwordAuth:
		return c.Password
	case tokenAuth:
		return c.Token
	default:
		return ""
	}
}

var (
	// Parsing errors
	noClustersObjectError = errors.New("no 'clusters' object")
	noClusterEntriesError = errors.New("no 'cluster' entries found in data")
	noContextsObjectError = errors.New("no 'contexts' object")
	noContextsError       = errors.New("no context entries found in data")
	noUsersObjectError    = errors.New("no 'users' object")
	noUsersError          = errors.New("no user entries found in data")
)
