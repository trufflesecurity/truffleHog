package jdbc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"

	"github.com/lib/pq"
)

type postgresJDBC struct {
	conn   string
	params map[string]string
}

func (s *postgresJDBC) ping(ctx context.Context) pingResult {
	// It is crucial that we try to build a connection string ourselves before using the one we found. This is because
	// if the found connection string doesn't include a username, the driver will attempt to connect using the current
	// user's name, which will fail in a way that looks like a determinate failure, thus terminating the waterfall. In
	// contrast, when we build a connection string ourselves, if there's no username, we try 'postgres' instead, which
	// actually has a chance of working.
	return ping(ctx, "postgres", isPostgresErrorDeterminate,
		buildPostgresConnectionString(s.params, true),
		buildPostgresConnectionString(s.params, false),
	)
}

func isPostgresErrorDeterminate(err error) bool {
	// Postgres codes from https://www.postgresql.org/docs/current/errcodes-appendix.html
	if pqErr, isPostgresError := err.(*pq.Error); isPostgresError {
		switch pqErr.Code {
		case "28P01":
			// Invalid username/password
			return true
		case "3D000":
			// Unknown database
			return false // "Indeterminate" so that other connection variations will be tried
		case "3F000":
			// Unknown schema
			return false // "Indeterminate" so that other connection variations will be tried
		}
	}

	return false
}

func joinKeyValues(m map[string]string, sep string) string {
	var data []string
	for k, v := range m {
		if v == "" {
			continue
		}
		data = append(data, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(data, sep)
}

func parsePostgres(_ logContext.Context, subname string) (jdbc, error) {
	// expected form: [subprotocol:]//[user:password@]HOST[/DB][?key=val[&key=val]]

	if !strings.HasPrefix(subname, "//") {
		return nil, errors.New("expected host to start with //")
	}

	u, err := url.Parse(subname)
	if err != nil {
		return nil, err
	}

	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" {
		dbName = "postgres"
	}

	params := map[string]string{
		"host":            u.Host,
		"dbname":          dbName,
		"connect_timeout": "5",
	}

	if u.User != nil {
		params["user"] = u.User.Username()
		pass, set := u.User.Password()
		if set {
			params["password"] = pass
		}
	}

	if feature.NoVerifySsl.Load() {
		params["sslmode"] = "disable"
	} else if v := u.Query()["sslmode"]; len(v) > 0 {
		switch v[0] {
		// https://www.postgresql.org/docs/current/libpq-ssl.html#LIBPQ-SSL-PROTECTION
		case "disable", "allow", "prefer",
			"require", "verify-ca", "verify-full":
			params["sslmode"] = v[0]
		}
	}

	if v := u.Query().Get("user"); v != "" {
		params["user"] = v
	}

	if v := u.Query().Get("password"); v != "" {
		params["password"] = v
	}

	return &postgresJDBC{subname[2:], params}, nil
}

func buildPostgresConnectionString(params map[string]string, includeDbName bool) string {
	data := map[string]string{
		// default user
		"user": "postgres",
	}
	for key, val := range params {
		if key == "host" {
			if h, p, found := strings.Cut(val, ":"); found {
				data["host"] = h
				data["port"] = p
				continue
			}
		}
		data[key] = val
	}

	if !includeDbName {
		data["dbname"] = "postgres"
	}

	connStr := joinKeyValues(data, " ")

	return connStr
}
