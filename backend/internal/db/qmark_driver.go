package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strconv"
	"unicode"

	"github.com/jackc/pgx/v5/stdlib"
)

func init() {
	sql.Register("pgx-qmark", qmarkDriver{driver: stdlib.GetDefaultDriver()})
}

type qmarkDriver struct {
	driver driver.Driver
}

func (d qmarkDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.driver.Open(name)
	if err != nil {
		return nil, err
	}
	return qmarkConn{Conn: conn}, nil
}

type qmarkConn struct {
	driver.Conn
}

func (c qmarkConn) Prepare(query string) (driver.Stmt, error) {
	return c.Conn.Prepare(rewriteQMarks(query))
}

func (c qmarkConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	conn, ok := c.Conn.(driver.ConnPrepareContext)
	if !ok {
		return c.Prepare(query)
	}
	return conn.PrepareContext(ctx, rewriteQMarks(query))
}

func (c qmarkConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	conn, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return conn.ExecContext(ctx, rewriteQMarks(query), args)
}

func (c qmarkConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	conn, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return conn.QueryContext(ctx, rewriteQMarks(query), args)
}

func (c qmarkConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	conn, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, driver.ErrSkip
	}
	return conn.BeginTx(ctx, opts)
}

func (c qmarkConn) Ping(ctx context.Context) error {
	conn, ok := c.Conn.(driver.Pinger)
	if !ok {
		return nil
	}
	return conn.Ping(ctx)
}

func (c qmarkConn) ResetSession(ctx context.Context) error {
	conn, ok := c.Conn.(driver.SessionResetter)
	if !ok {
		return nil
	}
	return conn.ResetSession(ctx)
}

func (c qmarkConn) IsValid() bool {
	conn, ok := c.Conn.(driver.Validator)
	if !ok {
		return true
	}
	return conn.IsValid()
}

func (c qmarkConn) CheckNamedValue(value *driver.NamedValue) error {
	conn, ok := c.Conn.(driver.NamedValueChecker)
	if !ok {
		return driver.ErrSkip
	}
	return conn.CheckNamedValue(value)
}

func rewriteQMarks(query string) string {
	result := make([]rune, 0, len(query))
	next := 1
	inSingleQuote := false
	inDoubleQuote := false
	runes := []rune(query)
	for i := 0; i < len(runes); i++ {
		current := runes[i]
		switch current {
		case '\'':
			result = append(result, current)
			if !inDoubleQuote {
				if inSingleQuote && i+1 < len(runes) && runes[i+1] == '\'' {
					i++
					result = append(result, runes[i])
					continue
				}
				inSingleQuote = !inSingleQuote
			}
		case '"':
			result = append(result, current)
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '?':
			if inSingleQuote || inDoubleQuote {
				result = append(result, current)
				continue
			}
			j := i + 1
			for j < len(runes) && unicode.IsDigit(runes[j]) {
				j++
			}
			if j > i+1 {
				result = append(result, '$')
				result = append(result, runes[i+1:j]...)
				i = j - 1
				continue
			}
			result = append(result, []rune("$"+strconv.Itoa(next))...)
			next++
		default:
			result = append(result, current)
		}
	}
	return string(result)
}

var (
	_ driver.Driver             = qmarkDriver{}
	_ driver.Conn               = qmarkConn{}
	_ driver.ConnPrepareContext = qmarkConn{}
	_ driver.ExecerContext      = qmarkConn{}
	_ driver.QueryerContext     = qmarkConn{}
	_ driver.ConnBeginTx        = qmarkConn{}
	_ driver.Pinger             = qmarkConn{}
	_ driver.SessionResetter    = qmarkConn{}
	_ driver.Validator          = qmarkConn{}
	_ driver.NamedValueChecker  = qmarkConn{}
)
