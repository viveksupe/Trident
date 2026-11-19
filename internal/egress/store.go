// Package egress implements the human-in-the-loop egress allowlist flow:
// actors ask (via a pre-approved callback host), a human approves in the
// shim console, and the shim patches the actor's substrate egress policy —
// with optional TTLs that auto-revoke.
package egress

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Request statuses.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusTimedOut = "timed_out"
)

// Request is one human-approval ask from an actor.
type Request struct {
	ID        int64     `json:"id"`
	Atespace  string    `json:"atespace"`
	ActorName string    `json:"actor_name"`
	Host      string    `json:"host"`
	Reason    string    `json:"reason"`
	Status    string    `json:"status"`
	Created   time.Time `json:"created"`
	Decided   time.Time `json:"decided"`
}

// Grant is an approved, live egress rule with an optional expiry.
type Grant struct {
	ID        int64     `json:"id"`
	RequestID int64     `json:"request_id"`
	Atespace  string    `json:"atespace"`
	ActorName string    `json:"actor_name"`
	Host      string    `json:"host"`
	Granted   time.Time `json:"granted"`
	Expires   time.Time `json:"expires"` // zero = until revoked
	Revoked   time.Time `json:"revoked"` // zero = live
}

// Store persists requests and grants.
type Store struct {
	db *sql.DB
}

// Open creates the schema in path (WAL, same conventions as sessionmap).
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open egress store: %w", err)
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS egress_requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			atespace TEXT NOT NULL, actor_name TEXT NOT NULL,
			host TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			created INTEGER NOT NULL, decided INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS egress_autos (
			actor_name TEXT PRIMARY KEY,
			ttl_seconds INTEGER NOT NULL DEFAULT 0,
			created INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS egress_grants (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_id INTEGER NOT NULL,
			atespace TEXT NOT NULL, actor_name TEXT NOT NULL,
			host TEXT NOT NULL,
			granted INTEGER NOT NULL, expires INTEGER NOT NULL DEFAULT 0,
			revoked INTEGER NOT NULL DEFAULT 0
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return nil, fmt.Errorf("egress store schema: %w", err)
		}
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// InsertRequest records a new pending request and returns its id.
func (s *Store) InsertRequest(r *Request) error {
	res, err := s.db.Exec(
		`INSERT INTO egress_requests(atespace,actor_name,host,reason,created) VALUES(?,?,?,?,?)`,
		r.Atespace, r.ActorName, r.Host, r.Reason, time.Now().UnixNano())
	if err != nil {
		return err
	}
	r.ID, err = res.LastInsertId()
	return err
}

// PendingPaged returns one page of pending requests (oldest first) and the
// total count.
func (s *Store) PendingPaged(limit, offset int) ([]Request, int, error) {
	if limit <= 0 {
		limit = 25
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM egress_requests WHERE status='pending'`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT id,atespace,actor_name,host,reason,status,created,decided
		FROM egress_requests WHERE status='pending' ORDER BY id ASC LIMIT ? OFFSET ?`,
		limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		var r Request
		var created, decided int64
		if err := rows.Scan(&r.ID, &r.Atespace, &r.ActorName, &r.Host, &r.Reason,
			&r.Status, &created, &decided); err != nil {
			return nil, 0, err
		}
		r.Created, r.Decided = time.Unix(0, created), time.Unix(0, decided)
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// Pending lists requests awaiting a decision, oldest first.
func (s *Store) Pending() ([]Request, error) {
	return s.list(`SELECT id,atespace,actor_name,host,reason,status,created,decided
		FROM egress_requests WHERE status='pending' ORDER BY id ASC`)
}

// History lists decided requests and live grants, newest first (console feed).
func (s *Store) History(limit int) ([]Request, error) {
	return s.list(fmt.Sprintf(
		`SELECT id,atespace,actor_name,host,reason,status,created,decided
		 FROM egress_requests WHERE status<>'pending' ORDER BY id DESC LIMIT %d`, limit))
}

func (s *Store) list(q string) ([]Request, error) {
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		var r Request
		var created, decided int64
		if err := rows.Scan(&r.ID, &r.Atespace, &r.ActorName, &r.Host, &r.Reason,
			&r.Status, &created, &decided); err != nil {
			return nil, err
		}
		r.Created, r.Decided = time.Unix(0, created), time.Unix(0, decided)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Decide transitions a pending request (idempotent: unknown/expired ids error).
func (s *Store) Decide(id int64, status string) (Request, error) {
	res, err := s.db.Exec(
		`UPDATE egress_requests SET status=?, decided=? WHERE id=? AND status='pending'`,
		status, time.Now().UnixNano(), id)
	if err != nil {
		return Request{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Request{}, fmt.Errorf("request %d is not pending", id)
	}
	r, err := s.getRequest(id)
	if err != nil {
		return Request{}, err
	}
	// Only approvals create a grant; denies and timeouts do not open egress.
	if status == StatusApproved {
		// Fresh grant starts permanent; the Manager narrows it via SetTTL.
		if _, err := s.db.Exec(
			`INSERT INTO egress_grants(request_id,atespace,actor_name,host,granted,expires)
			 SELECT id,atespace,actor_name,host,?,0 FROM egress_requests WHERE id=?`,
			r.Decided.UnixNano(), r.ID); err != nil {
			return r, err
		}
	}
	return r, nil
}

// SetTTL narrows the freshly created grant: expiry is decided by the caller
// (the manager knows the requested TTL), not the status string.
func (s *Store) SetTTL(requestID int64, expires time.Time) error {
	_, err := s.db.Exec(
		`UPDATE egress_grants SET expires=?
		 WHERE id = (SELECT id FROM egress_grants WHERE request_id=? AND revoked=0
		             ORDER BY id DESC LIMIT 1)`, expires.UnixNano(), requestID)
	return err
}

// getRequest re-reads one request.
func (s *Store) getRequest(id int64) (Request, error) {
	rows, err := s.list(fmt.Sprintf(
		`SELECT id,atespace,actor_name,host,reason,status,created,decided
		 FROM egress_requests WHERE id=%d`, id))
	if err != nil {
		return Request{}, err
	}
	if len(rows) != 1 {
		return Request{}, fmt.Errorf("request %d disappeared", id)
	}
	return rows[0], nil
}

// ClearHistory deletes decided requests and closed (revoked/expired) grants.
// Pending requests and live grants are untouched.
func (s *Store) ClearHistory() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM egress_requests WHERE status<>'pending'`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	_, err = s.db.Exec(`DELETE FROM egress_grants WHERE revoked<>0 OR
		(expires<>0 AND expires < strftime('%s','now') * 1000000000)`)
	return n, err
}

// LivePaged returns one page of live grants (newest granted first) + total.
func (s *Store) LivePaged(limit, offset int) ([]Grant, int, error) {
	if limit <= 0 {
		limit = 25
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM egress_grants WHERE revoked=0`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT id,request_id,atespace,actor_name,host,granted,expires,revoked
		FROM egress_grants WHERE revoked=0 ORDER BY granted DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		var granted, expires, revoked int64
		if err := rows.Scan(&g.ID, &g.RequestID, &g.Atespace, &g.ActorName, &g.Host,
			&granted, &expires, &revoked); err != nil {
			return nil, 0, err
		}
		g.Granted, g.Expires = time.Unix(0, granted), time.Unix(0, expires)
		if revoked != 0 {
			g.Revoked = time.Unix(0, revoked)
		}
		out = append(out, g)
	}
	return out, total, rows.Err()
}

// HistoryPaged returns one page of decided requests (newest first) + total.
func (s *Store) HistoryPaged(limit, offset int) ([]Request, int, error) {
	if limit <= 0 {
		limit = 25
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM egress_requests WHERE status<>'pending'`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT id,atespace,actor_name,host,reason,status,created,decided
		FROM egress_requests WHERE status<>'pending' ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		var r Request
		var created, decided int64
		if err := rows.Scan(&r.ID, &r.Atespace, &r.ActorName, &r.Host, &r.Reason,
			&r.Status, &created, &decided); err != nil {
			return nil, 0, err
		}
		r.Created, r.Decided = time.Unix(0, created), time.Unix(0, decided)
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// Live returns grants not yet revoked.
func (s *Store) Live() ([]Grant, error) {
	rows, err := s.db.Query(`SELECT id,request_id,atespace,actor_name,host,granted,expires,revoked
		FROM egress_grants WHERE revoked=0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		var granted, expires, revoked int64
		if err := rows.Scan(&g.ID, &g.RequestID, &g.Atespace, &g.ActorName, &g.Host,
			&granted, &expires, &revoked); err != nil {
			return nil, err
		}
		g.Granted, g.Expires = time.Unix(0, granted), time.Unix(0, expires)
		if revoked != 0 {
			g.Revoked = time.Unix(0, revoked)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// MarkRevoked stamps a grant as revoked.
func (s *Store) MarkRevoked(id int64) error {
	_, err := s.db.Exec(`UPDATE egress_grants SET revoked=? WHERE id=? AND revoked=0`,
		time.Now().UnixNano(), id)
	return err
}

// GrantForRequest returns the newest live grant created for a request.
func (s *Store) GrantForRequest(requestID int64) (Grant, error) {
	rows, err := s.db.Query(`SELECT id,request_id,atespace,actor_name,host,granted,expires,revoked
		FROM egress_grants WHERE request_id=? ORDER BY id DESC LIMIT 1`, requestID)
	if err != nil {
		return Grant{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return Grant{}, fmt.Errorf("no grant for request %d", requestID)
	}
	var g Grant
	var granted, expires, revoked int64
	if err := rows.Scan(&g.ID, &g.RequestID, &g.Atespace, &g.ActorName, &g.Host,
		&granted, &expires, &revoked); err != nil {
		return Grant{}, err
	}
	g.Granted, g.Expires = time.Unix(0, granted), time.Unix(0, expires)
	if revoked != 0 {
		g.Revoked = time.Unix(0, revoked)
	}
	return g, nil
}

// SetHost updates the allowlist hostname of a request (human correction of
// IP-only gateway observations).
func (s *Store) SetHost(id int64, host string) error {
	_, err := s.db.Exec(`UPDATE egress_requests SET host=? WHERE id=?`, host, id)
	return err
}

// PendingFor returns the pending request matching actor+host, plus its id.
func (s *Store) PendingFor(actor, host string) ([]Request, error) {
	rows, err := s.db.Query(`SELECT id,atespace,actor_name,host,reason,status,created,decided
		FROM egress_requests WHERE status='pending' AND actor_name=? AND host=?`, actor, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		var r Request
		var created, decided int64
		if err := rows.Scan(&r.ID, &r.Atespace, &r.ActorName, &r.Host, &r.Reason,
			&r.Status, &created, &decided); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AutoRule grants an actor self-service egress: its requests are approved
// automatically, each with the rule's TTL (0 = no expiry).
type AutoRule struct {
	ActorName string    `json:"actor_name"`
	TTL       int64     `json:"ttl_seconds"` // seconds; 0 = permanent
	Created   time.Time `json:"created"`
}

// SetAuto registers (or updates) an auto-approve rule for actor.
func (s *Store) SetAuto(actor string, ttlSeconds int64) error {
	_, err := s.db.Exec(
		`INSERT INTO egress_autos(actor_name,ttl_seconds,created) VALUES(?,?,?)
		 ON CONFLICT(actor_name) DO UPDATE SET ttl_seconds=excluded.ttl_seconds`,
		actor, ttlSeconds, time.Now().UnixNano())
	return err
}

// ClearAuto removes the auto-approve rule for actor.
func (s *Store) ClearAuto(actor string) error {
	_, err := s.db.Exec(`DELETE FROM egress_autos WHERE actor_name=?`, actor)
	return err
}

// AutosPaged returns one page of auto rules + total.
func (s *Store) AutosPaged(limit, offset int) ([]AutoRule, int, error) {
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM egress_autos`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT actor_name,ttl_seconds,created FROM egress_autos
		ORDER BY actor_name LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AutoRule
	for rows.Next() {
		var a AutoRule
		var created int64
		if err := rows.Scan(&a.ActorName, &a.TTL, &created); err != nil {
			return nil, 0, err
		}
		a.Created = time.Unix(0, created)
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// Autos lists the auto-approve rules.
func (s *Store) Autos() ([]AutoRule, error) {
	rows, err := s.db.Query(`SELECT actor_name,ttl_seconds,created FROM egress_autos ORDER BY actor_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AutoRule
	for rows.Next() {
		var a AutoRule
		var created int64
		if err := rows.Scan(&a.ActorName, &a.TTL, &created); err != nil {
			return nil, err
		}
		a.Created = time.Unix(0, created)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AutoFor returns the auto rule for actor, if any.
func (s *Store) AutoFor(actor string) (AutoRule, bool, error) {
	autos, err := s.Autos()
	if err != nil {
		return AutoRule{}, false, err
	}
	for _, a := range autos {
		if a.ActorName == actor {
			return a, true, nil
		}
	}
	return AutoRule{}, false, nil
}
