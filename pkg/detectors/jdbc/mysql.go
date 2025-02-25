package jdbc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"

	"github.com/go-sql-driver/mysql"
)

type mysqlJDBC struct {
	conn     string
	userPass string
	host     string
	params   string
}

func (s *mysqlJDBC) ping(ctx context.Context) pingResult {
	return ping(ctx, "mysql", isMySQLErrorDeterminate,
		buildMySQLConnectionString(s.host, "", s.userPass, s.params))
}

func buildMySQLConnectionString(host, database, userPass, params string) string {
	conn := host + "/" + database
	if userPass != "" {
		conn = userPass + "@" + conn
	}
	if params != "" {
		conn = conn + "?" + params
	}
	return conn
}

func isMySQLErrorDeterminate(err error) bool {
	// MySQL error numbers from https://dev.mysql.com/doc/mysql-errors/8.0/en/server-error-reference.html
	if mySQLErr, isMySQLErr := err.(*mysql.MySQLError); isMySQLErr {
		switch mySQLErr.Number {
		case 1044:
			// User access denied to a particular database
			return false // "Indeterminate" so that other connection variations will be tried
		case 1045:
			// User access denied
			return true
		}
	}

	return false
}

const defaultParams = "timeout=5s"

func parseMySQL(_ logContext.Context, subname string) (jdbc, error) {
	// expected form: [subprotocol:]//[user:password@]HOST[/DB][?key=val[&key=val]]
	if !strings.HasPrefix(subname, "//") {
		return nil, errors.New("expected host to start with //")
	}

	params := defaultParams
	if feature.NoVerifySsl.Load() {
		params = defaultParams + "&tls=skip-verify"
	}

	// need for hostnames that have tcp(host:port) format required by this database driver
	cfg, err := mysql.ParseDSN(strings.TrimPrefix(subname, "//"))
	if err == nil {
		return &mysqlJDBC{
			conn:     subname[2:],
			userPass: cfg.User + ":" + cfg.Passwd,
			host:     fmt.Sprintf("tcp(%s)", cfg.Addr),
			params:   params,
		}, nil
	}

	// for standard URI format, which is all i've seen for JDBC
	u, err := url.Parse(subname)
	if err != nil {
		return nil, err
	}

	user := "root"
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}

	if v := u.Query().Get("user"); v != "" {
		user = v
	}
	if v := u.Query().Get("password"); v != "" {
		pass = v
	}

	userAndPass := user
	if pass != "" {
		userAndPass = userAndPass + ":" + pass
	}

	return &mysqlJDBC{
		conn:     subname[2:],
		userPass: userAndPass,
		host:     fmt.Sprintf("tcp(%s)", u.Host),
		params:   params,
	}, nil

}
