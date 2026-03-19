package db

import (
	"embed"
	"fmt"
	"strings"

	"github.com/veilkey/veilkey-go-package/dbutil"
	"gorm.io/gorm"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type DB struct {
	conn *gorm.DB
}

func New(dbPath string) (*DB, error) {
	conn, err := dbutil.OpenGORM(dbPath)
	if err != nil {
		return nil, err
	}

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, err
	}
	return db, nil
}

func (d *DB) migrate() error {
	if err := d.conn.Exec(`CREATE TABLE IF NOT EXISTS migrations (
		filename   TEXT PRIMARY KEY,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`).Error; err != nil {
		return err
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		filename := entry.Name()

		var count int64
		d.conn.Raw(`SELECT COUNT(*) FROM migrations WHERE filename = ?`, filename).Scan(&count)
		if count > 0 {
			continue
		}

		sqlBytes, err := migrationsFS.ReadFile("migrations/" + filename)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", filename, err)
		}
		if err := d.conn.Exec(string(sqlBytes)).Error; err != nil {
			return fmt.Errorf("migration %s failed: %w", filename, err)
		}
		if err := d.conn.Exec(`INSERT INTO migrations (filename) VALUES (?)`, filename).Error; err != nil {
			return fmt.Errorf("record migration %s: %w", filename, err)
		}
	}

	return nil
}

func (d *DB) Close() error {
	sqlDB, err := d.conn.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (d *DB) Ping() error {
	sqlDB, err := d.conn.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}
