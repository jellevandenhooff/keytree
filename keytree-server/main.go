package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/jellevandenhooff/keytree/dkimproof"
	"github.com/jellevandenhooff/keytree/dns"
	"github.com/jellevandenhooff/keytree/mirror"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/updaterules"

	"golang.org/x/net/context"
)

type Status struct {
	PublicKey  string
	Upstream   []ServerInfo
	TotalNodes int
}

type CloserReader struct {
	io.Reader
	io.Closer
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	parseFlags()

	if catchUpRecoveryEnabled {
		log.Println("recovery enabled... after recovering, restart without recover flag!")
	}

	socket, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("couldn't bind to %s: %s\n", socket, err)
	}
	log.Printf("listening on %s\n", *listenAddr)

	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		log.Fatalf("couldn't create %s: %s\n", *dataDir, err)
	}

	configPath := filepath.Join(*dataDir, configName)
	databasePath := filepath.Join(*dataDir, databaseName)

	config, signer, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("could not open config: %s\n", err)
	}

	db, err := OpenDB(databasePath)
	if err != nil {
		log.Fatalf("could not open db: %s\n", err)
	}
	root, err := db.Load()
	if err != nil {
		log.Fatalf("failed to read database: %s\n", err)
	}

	dedup := trie.NewDedup()
	coordinator := mirror.NewCoordinator(dedup)

	reconcileLocks := newHashLocker()

	trieCache := newTrieCache(dedup, updateBatchBacklog)
	updateCache := newUpdateCache(root.Hash())

	trackers := make(map[string]*tracker)
	allTries := make(map[string]*lookupTrie)

	dnsClient := &dns.SimpleDNSClient{
		Server: config.DNSServer,
	}

	s := &Server{
		config: config,
		signer: signer,

		reconcileLocks: reconcileLocks,

		dedup:       dedup,
		coordinator: coordinator,

		db:        db,
		localTrie: nil,

		updateCache:    updateCache,
		trieCache:      trieCache,
		updateRequests: make(chan updateRequest, updateQueueSize),

		trackers: trackers,
		allTries: allTries,

		verifier: updaterules.NewVerifier(dnsClient),
	}
	s.setAndSignRoot(root)

	go s.processUpdates()
	go s.follow(context.Background())

	dkimServer, err := dkimproof.RunServer("keytree.io", dnsClient)
	if err != nil {
		log.Printf("could not start DKIM server: %s", err)
	}

	mux := http.NewServeMux()

	s.addHandlers(mux)
	dkimServer.AddHandlers(mux)
	// http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	server := &http.Server{
		ReadTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = CloserReader{
				Closer: r.Body,
				Reader: io.LimitReader(r.Body, 64*1024),
			}
			mux.ServeHTTP(w, r)
		}),
	}

	server.Serve(socket)
}
