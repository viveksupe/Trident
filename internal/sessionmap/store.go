// Package sessionmap persists chat→actor mappings so a shim restart does not
// orphan suspended substrate actors (which would otherwise leak until MaxAge).
package sessionmap

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/viveksupe/Trident/internal/model"
)

// Entry is one persisted chat→actor row.
type Entry struct {
	UserID    string    `json:"user_id"`
	ChatID    string    `json:"chat_id"`
	ActorName string    `json:"actor_name"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"` // zero when never recorded
}

// Key renders the sqlite primary key.
func (e Entry) key() string {
	data, _ := json.Marshal(e.UserID + "\x00" + e.ChatID)
	return string(data)
}

// Store is a sqlite-backed session map. In-memory state is authoritative for
// reads (the pool keeps it hot); writes happen-through so a restart can reload.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

// Open opens (creating if needed) the session map database.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sessionmap: %w", err)
	}
	defer func() {
		if db != nil {
			_ = db.Close() // schema set-up failed: don't leak the handle
		}
	}()
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			key BLOB PRIMARY KEY,
			user_id TEXT NOT NULL,
			chat_id TEXT NOT NULL,
			actor_name TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS sessions_actor ON sessions(actor_name)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return nil, fmt.Errorf("sessionmap schema: %w", err)
		}
	}
	// last_active: added in-flight to power the console's purge/suspend ETAs;
	// fails benignly when the column already exists.
	_, _ = db.Exec(`ALTER TABLE sessions ADD COLUMN last_active INTEGER`)
	s := &Store{db: db}
	db = nil // ownership transferred
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Put upserts a mapping.
func (s *Store) Put(e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO sessions(key,user_id,chat_id,actor_name,created_at) VALUES(?,?,?,?,?)
		 ON CONFLICT(key) DO UPDATE SET actor_name=excluded.actor_name`,
		e.key(), e.UserID, e.ChatID, e.ActorName, e.CreatedAt.UnixNano())
	if err != nil {
		return fmt.Errorf("sessionmap put: %w", err)
	}
	return nil
}

// Delete removes a mapping by route key.
func (s *Store) Delete(key model.RouteKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id=? AND chat_id=?`, key.UserID, key.ChatID)
	return err
}

// SetLastSeen records the latest activity for key (drives console ETAs).
func (s *Store) SetLastSeen(key model.RouteKey, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE sessions SET last_active=? WHERE user_id=? AND chat_id=?`,
		at.UnixNano(), key.UserID, key.ChatID)
	return err
}

// SetLastSeenBatch records several keys' latest activity in one transaction
// (the pool buffers per-request activity and flushes it here, off the hot
// path).
func (s *Store) SetLastSeenBatch(entries map[model.RouteKey]time.Time) error {
	if len(entries) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`UPDATE sessions SET last_active=? WHERE user_id=? AND chat_id=?`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	for key, at := range entries {
		if _, err := stmt.Exec(at.UnixNano(), key.UserID, key.ChatID); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return err
		}
	}
	_ = stmt.Close()
	return tx.Commit()
}

// LatestActor returns the actor mapping for key, if any.
func (s *Store) LatestActor(key model.RouteKey) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var name string
	err := s.db.QueryRow(`SELECT actor_name FROM sessions WHERE user_id=? AND chat_id=?`,
		key.UserID, key.ChatID).Scan(&name)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return name, true, nil
}

// All returns every mapping (keyed by RouteKey) for restart reconciliation.
func (s *Store) All() (map[model.RouteKey]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT user_id,chat_id,actor_name,created_at,COALESCE(last_active,0) FROM sessions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[model.RouteKey]Entry{}
	for rows.Next() {
		var e Entry
		var createdNano, lastNano int64
		if err := rows.Scan(&e.UserID, &e.ChatID, &e.ActorName, &createdNano, &lastNano); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(0, createdNano)
		if lastNano > 0 {
			e.LastSeen = time.Unix(0, lastNano)
		}
		out[model.RouteKey{UserID: e.UserID, ChatID: e.ChatID}] = e
	}
	return out, rows.Err()
}

// Prune removes mappings for route keys absent from keep.
func (s *Store) Prune(keep map[model.RouteKey]Entry) error {
	all, err := s.All()
	if err != nil {
		return err
	}
	for key := range all {
		if _, ok := keep[key]; !ok {
			if err := s.Delete(key); err != nil {
				return err
			}
		}
	}
	return nil
}
