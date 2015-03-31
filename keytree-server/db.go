package main

import (
	"encoding/json"
	"errors"
	"os"
	"runtime"

	"github.com/boltdb/bolt"
	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/encoding"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/wire"
)

type DB interface {
	Load() (*trie.Node, error)

	Read(name crypto.Hash) (*wire.SignedEntry, error)
	ReadSince(name crypto.Hash, timestamp uint64) (*wire.SignedEntry, error)

	PerformUpdates(updates []*wire.SignedEntry) error

	Close() error
}

// Database schema:
// entries/<entry-hash>/<entry-timestamp> -> JSON wire.SignedEntry
// info/schema-version                    -> uint64 schemaVersion
const schemaVersion = 8

type boltDb struct {
	db *bolt.DB
}

func initializeDb(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucket([]byte("entries")); err != nil {
			return err
		}
		bucket, err := tx.CreateBucket([]byte("info"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("schema-version"), encoding.EncodeBEUint64(schemaVersion))
	})
	return nil
}

func checkSchemaVersionDb(db *bolt.DB) error {
	return db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("info"))
		if bucket == nil {
			return errors.New("missing info bucket")
		}
		version := bucket.Get([]byte("schema-version"))
		if encoding.DecodeBEUint64(version) != schemaVersion {
			return errors.New("invalid database schema version")
		}
		return nil
	})
}

func OpenDB(path string) (DB, error) {
	didExist := true
	if _, err := os.Stat(path); os.IsNotExist(err) {
		didExist = false
	}

	db, err := bolt.Open(path, 0644, nil)
	if err != nil {
		return nil, err
	}

	if !didExist {
		if err := initializeDb(db); err != nil {
			db.Close()
			return nil, err
		}
	}

	if err := checkSchemaVersionDb(db); err != nil {
		db.Close()
		return nil, err
	}

	return &boltDb{
		db: db,
	}, nil
}

func (b *boltDb) Read(name crypto.Hash) (update *wire.SignedEntry, err error) {
	err = b.db.View(func(tx *bolt.Tx) error {
		entries := tx.Bucket([]byte("entries"))
		bucket := entries.Bucket(name.Bytes())
		if bucket == nil {
			return nil
		}

		c := bucket.Cursor()
		_, v := c.Last()
		if v == nil {
			return nil
		}
		update = new(wire.SignedEntry)
		return json.Unmarshal(v, update)
	})
	return
}

func (b *boltDb) ReadSince(name crypto.Hash, timestamp uint64) (update *wire.SignedEntry, err error) {
	err = b.db.View(func(tx *bolt.Tx) error {
		entries := tx.Bucket([]byte("entries"))
		bucket := entries.Bucket(name.Bytes())
		if bucket == nil {
			return nil
		}

		c := bucket.Cursor()
		_, v := c.Seek(encoding.EncodeBEUint64(timestamp))
		if v == nil {
			return nil
		}
		update = new(wire.SignedEntry)
		return json.Unmarshal(v, update)
	})
	return
}

func writeUpdate(tx *bolt.Tx, update *wire.SignedEntry) error {
	entries := tx.Bucket([]byte("entries"))
	bucket, err := entries.CreateBucketIfNotExists(crypto.HashString(update.Entry.Name).Bytes())
	if err != nil {
		return err
	}

	// Store the entry.
	bytes, err := json.Marshal(update)
	if err != nil {
		return err
	}
	versionBytes := encoding.EncodeBEUint64(update.Entry.Timestamp)
	return bucket.Put(versionBytes, bytes)
}

func (b *boltDb) PerformUpdates(updates []*wire.SignedEntry) error {
	if len(updates) == 0 {
		return nil
	}

	return b.db.Update(func(tx *bolt.Tx) error {
		for _, update := range updates {
			writeUpdate(tx, update)
		}
		return nil
	})
}

func (b *boltDb) Load() (root *trie.Node, err error) {
	err = b.db.View(func(tx *bolt.Tx) error {
		root = nil
		entries := tx.Bucket([]byte("entries"))

		c := entries.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			_, v := entries.Bucket(k).Cursor().Last()

			var update wire.SignedEntry
			if err := json.Unmarshal(v, &update); err != nil {
				return err
			}

			leaf := update.Entry.ToLeaf()
			root = root.Set(leaf.NameHash, leaf)
		}
		root.ParallelHash(runtime.NumCPU()) // force calculation of all hash values

		return nil
	})
	return
}

func (b *boltDb) Close() error {
	return b.db.Close()
}
