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
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open egress store: %w", err)
	}
	defer func() {
		if db != nil {
			_ = db.Close() // schema set-up failed: don't leak the handle
		}
	}()
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
	st := &Store{db: db}
	db = nil // ownership transferred
	return st, nil
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

// GrantForWild returns the live wildcard grant for actor, if any.
func (s *Store) GrantForWild(actor, host string) (*Grant, error) {
	rows, err := s.db.Query(`SELECT id,request_id,atespace,actor_name,host,granted,expires,revoked
		FROM egress_grants WHERE actor_name=? AND host=? AND revoked=0 ORDER BY id DESC LIMIT 1`, actor, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	var g Grant
	var granted, expires, revoked int64
	if err := rows.Scan(&g.ID, &g.RequestID, &g.Atespace, &g.ActorName, &g.Host, &granted, &expires, &revoked); err != nil {
		return nil, err
	}
	g.Granted, g.Expires = time.Unix(0, granted), time.Unix(0, expires)
	if revoked != 0 {
		g.Revoked = time.Unix(0, revoked)
	}
	return &g, nil
}

// InsertWildGrant records a wildcard grant (no originating request).
func (s *Store) InsertWildGrant(atespace, actor, host string, ttl time.Duration) error {
	expires := int64(0)
	if ttl > 0 {
		expires = time.Now().Add(ttl).UnixNano()
	}
	_, err := s.db.Exec(
		`INSERT INTO egress_grants(request_id,atespace,actor_name,host,granted,expires) VALUES(0,?,?,?,?,?)`,
		atespace, actor, host, time.Now().UnixNano(), expires)
	return err
}

// SetWildTTL narrows a wildcard grant's expiry.
func (s *Store) SetWildTTL(id int64, expires time.Time) error {
	_, err := s.db.Exec(`UPDATE egress_grants SET expires=? WHERE id=?`, expires.UnixNano(), id)
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

// PurgeActor removes every egress bookkeeping row for actor: pending
// requests, grant records, standing auto rules.
func (s *Store) PurgeActor(actor string) error {
	for _, stmt := range []string{
		`DELETE FROM egress_requests WHERE actor_name=?`,
		`DELETE FROM egress_grants WHERE actor_name=?`,
		`DELETE FROM egress_autos WHERE actor_name=?`,
	} {
		if _, err := s.db.Exec(stmt, actor); err != nil {
			return err
		}
	}
	return nil
}

// Pending lists requests awaiting a decision, oldest first.
func (s *Store) Pending() ([]Request, error) {
	return s.list(`SELECT id,atespace,actor_name,host,reason,status,created,decided
		FROM egress_requests WHERE status='pending' ORDER BY id ASC`)
}

// History lists decided requests, newest first (console feed).
func (s *Store) History(limit int) ([]Request, error) {
	rows, err := s.db.Query(
		`SELECT id,atespace,actor_name,host,reason,status,created,decided
		 FROM egress_requests WHERE status<>'pending' ORDER BY id DESC LIMIT ?`, limit)
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
// Only denial / timeout paths use it — approvals go through DecideApproved,
// which keeps the request, grant and TTL in one transaction.
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
	return s.getRequest(id)
}

// DecideApproved atomically marks the request approved, inserts its grant,
// and stamps the requested expiry. The manager patches the policy BEFORE
// calling this, so status/grant-row drift is impossible.
func (s *Store) DecideApproved(id int64, ttl time.Duration) (Request, Grant, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Request{}, Grant{}, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	now := time.Now().UnixNano()
	res, err := tx.Exec(
		`UPDATE egress_requests SET status=?, decided=? WHERE id=? AND status='pending'`,
		StatusApproved, now, id)
	if err != nil {
		return Request{}, Grant{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Request{}, Grant{}, fmt.Errorf("request %d is not pending", id)
	}
	expires := int64(0)
	if ttl > 0 {
		expires = time.Now().Add(ttl).UnixNano()
	}
	gres, err := tx.Exec(
		`INSERT INTO egress_grants(request_id,atespace,actor_name,host,granted,expires)
		 SELECT id,atespace,actor_name,host,?,? FROM egress_requests WHERE id=?`,
		now, expires, id)
	if err != nil {
		return Request{}, Grant{}, fmt.Errorf("grant insert for request %d: %w", id, err)
	}
	grantID, err := gres.LastInsertId()
	if err != nil {
		return Request{}, Grant{}, err
	}
	rows, err := tx.Query(
		`SELECT id,atespace,actor_name,host,reason,status,created,decided
		 FROM egress_requests WHERE id=?`, id)
	if err != nil {
		return Request{}, Grant{}, err
	}
	var r Request
	var created, decided int64
	if rows.Next() {
		if err := rows.Scan(&r.ID, &r.Atespace, &r.ActorName, &r.Host, &r.Reason,
			&r.Status, &created, &decided); err != nil {
			rows.Close()
			return Request{}, Grant{}, err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Request{}, Grant{}, err
	}
	r.Created, r.Decided = time.Unix(0, created), time.Unix(0, decided)
	var g Grant
	var granted int64
	err = tx.QueryRow(
		`SELECT id,request_id,atespace,actor_name,host,granted,expires,revoked
		 FROM egress_grants WHERE id=?`, grantID).Scan(
		&g.ID, &g.RequestID, &g.Atespace, &g.ActorName, &g.Host, &granted, &expires, new(int64))
	if err != nil {
		return Request{}, Grant{}, err
	}
	g.Granted = time.Unix(0, granted)
	if expires != 0 {
		g.Expires = time.Unix(0, expires)
	}
	if err := tx.Commit(); err != nil {
		return Request{}, Grant{}, err
	}
	tx = nil
	return r, g, nil
}

// getRequest re-reads one request.
func (s *Store) getRequest(id int64) (Request, error) {
	rows, err := s.list(
		`SELECT id,atespace,actor_name,host,reason,status,created,decided
		 FROM egress_requests WHERE id=?`, id)
	if err != nil {
		return Request{}, err
	}
	if len(rows) != 1 {
		return Request{}, fmt.Errorf("request %d disappeared", id)
	}
	return rows[0], nil
}

// GetRequest returns one request by id (any status), or nil — the console
// and the actor's status poll stop walking paged lists.
func (s *Store) GetRequest(id int64) (*Request, error) {
	rows, err := s.list(
		`SELECT id,atespace,actor_name,host,reason,status,created,decided
		 FROM egress_requests WHERE id=?`, id)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// PendingCountForActor reports the actor's open request count (per-actor
// flood cap).
func (s *Store) PendingCountForActor(actor string) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM egress_requests WHERE status='pending' AND actor_name=?`,
		actor).Scan(&n)
	return n, err
}

// PendingCount reports the GLOBAL open-request count (global flood cap).
func (s *Store) PendingCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM egress_requests WHERE status='pending'`).Scan(&n)
	return n, err
}

// list runs a query with optional args and scans requests.
func (s *Store) list(q string, args ...any) ([]Request, error) {
	rows, err := s.db.Query(q, args...)
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

// ClearHistory drops decided requests and closed (revoked) grants. Pending
// requests and live grants are untouched — grants that expired but have not
// been swept yet still carry policy rules, so they are never deleted here
// (the revoke ticker closes them first).
func (s *Store) ClearHistory() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM egress_requests WHERE status<>'pending'`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	_, err = s.db.Exec(`DELETE FROM egress_grants WHERE revoked<>0`)
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

// Live returns every unrevoked grant, oldest first (stable order: revoke
// loops enumerate this list once; each decision then re-reads LiveFor).
func (s *Store) Live() ([]Grant, error) {
	rows, err := s.db.Query(`SELECT id,request_id,atespace,actor_name,host,granted,expires,revoked
		FROM egress_grants WHERE revoked=0 ORDER BY id ASC`)
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

// LiveFor returns the live grants for one (actor, host) pair, oldest first.
// It is the fresh read revoke decisions need: duplicate grants for the same
// host are normal, and a caller-side snapshot taken before a concurrent
// approval or revocation would mis-count who still holds the shared rule.
func (s *Store) LiveFor(actor, host string) ([]Grant, error) {
	rows, err := s.db.Query(`SELECT id,request_id,atespace,actor_name,host,granted,expires,revoked
		FROM egress_grants WHERE actor_name=? AND host=? AND revoked=0 ORDER BY id ASC`,
		actor, host)
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

// SetHost updates the allowlist hostname of a PENDING request (human
// correction of IP-only gateway observations). Decided requests are frozen.
func (s *Store) SetHost(id int64, host string) error {
	res, err := s.db.Exec(`UPDATE egress_requests SET host=? WHERE id=? AND status='pending'`,
		host, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("request %d is not pending", id)
	}
	return nil
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
