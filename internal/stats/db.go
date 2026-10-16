package stats

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"modernc.org/sqlite"
)

// The statistics live in dataDir/tamamo.db. A save replaces the whole content
// in one transaction, so an interrupted save leaves the previous state intact.

const (
	dbFile        = "tamamo.db"
	schemaVersion = "1"

	sqliteCorrupt = 11 // SQLITE_CORRUPT
	sqliteNotADB  = 26 // SQLITE_NOTADB
)

// counterCols lists the columns that mirror Counters, in struct order.
const counterCols = "requests, passed, allowed, challenged, solved, failed, blocked"

var (
	errClosed = errors.New("stats database is closed")
	errSchema = errors.New("unsupported stats database schema version")
)

var schema = []string{
	`CREATE TABLE IF NOT EXISTS meta (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS scopes (
		scope       TEXT PRIMARY KEY,
		requests    INTEGER NOT NULL,
		passed      INTEGER NOT NULL,
		allowed     INTEGER NOT NULL,
		challenged  INTEGER NOT NULL,
		solved      INTEGER NOT NULL,
		failed      INTEGER NOT NULL,
		blocked     INTEGER NOT NULL,
		solve_sum   INTEGER NOT NULL,
		solve_count INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS hours (
		scope      TEXT NOT NULL,
		t          INTEGER NOT NULL,
		requests   INTEGER NOT NULL,
		passed     INTEGER NOT NULL,
		allowed    INTEGER NOT NULL,
		challenged INTEGER NOT NULL,
		solved     INTEGER NOT NULL,
		failed     INTEGER NOT NULL,
		blocked    INTEGER NOT NULL,
		PRIMARY KEY (scope, t)
	)`,
	`CREATE TABLE IF NOT EXISTS tops (
		scope TEXT NOT NULL,
		list  TEXT NOT NULL,
		name  TEXT NOT NULL,
		count INTEGER NOT NULL,
		PRIMARY KEY (scope, list, name)
	)`,
	`CREATE TABLE IF NOT EXISTS events (
		id       INTEGER PRIMARY KEY AUTOINCREMENT,
		time     TEXT NOT NULL,
		kind     TEXT NOT NULL,
		site     TEXT NOT NULL,
		ip       TEXT NOT NULL,
		host     TEXT NOT NULL,
		path     TEXT NOT NULL,
		ua       TEXT NOT NULL,
		rule     TEXT NOT NULL,
		solve_ms INTEGER NOT NULL
	)`,
}

// openDB opens the statistics database at path, creating it if needed, and
// makes sure the schema is in place. Only one connection is used, so writes
// never contend with each other.
func openDB(path string) (*sql.DB, error) {
	// A plain path (no file: prefix) keeps Windows drive letters and spaces
	// literal; modernc.org/sqlite strips the query and applies the pragmas.
	dsn := filepath.ToSlash(path) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func initSchema(db *sql.DB) error {
	if err := db.Ping(); err != nil {
		return err
	}
	for _, q := range schema {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	var v string
	err := db.QueryRow(`SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = db.Exec(`INSERT INTO meta (key, value) VALUES ('schema_version', ?)`, schemaVersion)
		return err
	}
	if err != nil {
		return err
	}
	if v != schemaVersion {
		return fmt.Errorf("%w: %q", errSchema, v)
	}
	return nil
}

// isCorrupt reports whether err means the file is not a usable database (as
// opposed to, say, a missing directory or a permission problem).
func isCorrupt(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errSchema) {
		return true
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case sqliteCorrupt, sqliteNotADB:
			return true
		}
	}
	return false
}

// setAside renames a broken database (and its WAL files, which must not be
// replayed into a new database) out of the way, keeping it for inspection.
func setAside(path string) {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := path + suffix
		if err := os.Rename(src, src+".corrupt"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("moving broken stats database aside failed", "path", src, "err", err)
		}
	}
}

// hasData reports whether a save has ever completed in db.
func hasData(db *sql.DB) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM meta WHERE key = 'since'`).Scan(&n)
	return n > 0, err
}

// queryEach runs q and calls fn for every row.
func queryEach(db *sql.DB, q string, fn func(*sql.Rows) error, args ...any) error {
	rows, err := db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// readDB loads the whole statistics state from db.
func readDB(db *sql.DB) (*persisted, error) {
	p := &persisted{Sites: map[string]persistedBucket{}}

	var since string
	if err := db.QueryRow(`SELECT value FROM meta WHERE key = 'since'`).Scan(&since); err != nil {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339Nano, since)
	if err != nil {
		return nil, err
	}
	p.Since = t

	// Scope "" is the all-sites bucket; every other scope is a site ID.
	buckets := map[string]*persistedBucket{}
	get := func(scope string) *persistedBucket {
		pb := buckets[scope]
		if pb == nil {
			pb = &persistedBucket{bucket: *newBucket()}
			buckets[scope] = pb
		}
		return pb
	}

	err = queryEach(db, `SELECT scope, `+counterCols+`, solve_sum, solve_count FROM scopes`, func(r *sql.Rows) error {
		var scope string
		var c Counters
		var sum, cnt int64
		if err := r.Scan(&scope, &c.Requests, &c.Passed, &c.Allowed, &c.Challenged, &c.Solved, &c.Failed, &c.Blocked, &sum, &cnt); err != nil {
			return err
		}
		pb := get(scope)
		pb.Totals, pb.SolveSum, pb.SolveCount = c, sum, cnt
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = queryEach(db, `SELECT scope, t, `+counterCols+` FROM hours ORDER BY scope, t`, func(r *sql.Rows) error {
		var scope string
		var ht int64
		var c Counters
		if err := r.Scan(&scope, &ht, &c.Requests, &c.Passed, &c.Allowed, &c.Challenged, &c.Solved, &c.Failed, &c.Blocked); err != nil {
			return err
		}
		pb := get(scope)
		pb.HourList = append(pb.HourList, HourBucket{T: ht, Counters: c})
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = queryEach(db, `SELECT scope, list, name, count FROM tops`, func(r *sql.Rows) error {
		var scope, list, name string
		var n int64
		if err := r.Scan(&scope, &list, &name, &n); err != nil {
			return err
		}
		pb := get(scope)
		switch list {
		case "rules":
			pb.Rules[name] = n
		case "uas":
			pb.UAs[name] = n
		case "paths":
			pb.Paths[name] = n
		case "ips":
			pb.IPs[name] = n
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Events are stored oldest first; persisted keeps them newest first.
	err = queryEach(db, `SELECT time, kind, site, ip, host, path, ua, rule, solve_ms FROM events ORDER BY id DESC`, func(r *sql.Rows) error {
		var ts string
		var e Event
		if err := r.Scan(&ts, &e.Kind, &e.Site, &e.IP, &e.Host, &e.Path, &e.UA, &e.Rule, &e.SolveMs); err != nil {
			return err
		}
		if e.Time, err = time.Parse(time.RFC3339Nano, ts); err != nil {
			return err
		}
		p.Events = append(p.Events, e)
		return nil
	})
	if err != nil {
		return nil, err
	}

	for scope, pb := range buckets {
		if scope == "" {
			p.All = *pb
		} else {
			p.Sites[scope] = *pb
		}
	}
	return p, nil
}

// writeDB replaces the whole statistics state in db within one transaction.
func writeDB(db *sql.DB, p *persisted) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after Commit

	for _, table := range []string{"scopes", "hours", "tops", "events"} {
		if _, err := tx.Exec("DELETE FROM " + table); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('since', ?)`,
		p.Since.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}

	scopeStmt, err := tx.Prepare(`INSERT INTO scopes (scope, ` + counterCols + `, solve_sum, solve_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer scopeStmt.Close()
	hourStmt, err := tx.Prepare(`INSERT INTO hours (scope, t, ` + counterCols + `) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer hourStmt.Close()
	topStmt, err := tx.Prepare(`INSERT INTO tops (scope, list, name, count) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer topStmt.Close()
	eventStmt, err := tx.Prepare(`INSERT INTO events (time, kind, site, ip, host, path, ua, rule, solve_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer eventStmt.Close()

	writeScope := func(scope string, pb *persistedBucket) error {
		c := pb.Totals
		if _, err := scopeStmt.Exec(scope, c.Requests, c.Passed, c.Allowed, c.Challenged,
			c.Solved, c.Failed, c.Blocked, pb.SolveSum, pb.SolveCount); err != nil {
			return err
		}
		for _, h := range pb.HourList {
			hc := h.Counters
			if _, err := hourStmt.Exec(scope, h.T, hc.Requests, hc.Passed, hc.Allowed, hc.Challenged,
				hc.Solved, hc.Failed, hc.Blocked); err != nil {
				return err
			}
		}
		lists := []struct {
			name string
			m    map[string]int64
		}{{"rules", pb.Rules}, {"uas", pb.UAs}, {"paths", pb.Paths}, {"ips", pb.IPs}}
		for _, l := range lists {
			for name, n := range l.m {
				if _, err := topStmt.Exec(scope, l.name, name, n); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := writeScope("", &p.All); err != nil {
		return err
	}
	for id, pb := range p.Sites {
		if err := writeScope(id, &pb); err != nil {
			return err
		}
	}
	// Insert oldest first so ascending ids replay in order.
	for i := len(p.Events) - 1; i >= 0; i-- {
		e := p.Events[i]
		if _, err := eventStmt.Exec(e.Time.UTC().Format(time.RFC3339Nano), e.Kind, e.Site, e.IP,
			e.Host, e.Path, e.UA, e.Rule, e.SolveMs); err != nil {
			return err
		}
	}
	return tx.Commit()
}
