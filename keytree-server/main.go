package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"path/filepath"
	"runtime"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/dkimproof"
	"github.com/jellevandenhooff/keytree/dns"
	"github.com/jellevandenhooff/keytree/trie/dedup"
	"github.com/jellevandenhooff/keytree/trie/mirror"
	"github.com/jellevandenhooff/keytree/updaterules"

	"golang.org/x/net/context"

	_ "net/http/pprof"
)

type Status struct {
	PublicKey  string
	Upstream   []ServerInfo
	TotalNodes int
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

	dedup := dedup.New()
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

	rpc.RegisterName("KeyTree", s)
	dkimServer, err := dkimproof.RunServer("keytree.io", dnsClient)
	if err != nil {
		log.Printf("could not start DKIM server: %s", err)
	} else {
		rpc.RegisterName("DKIM", dkimServer)
	}
	rpc.HandleHTTP()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		history, _ := db.ReadSince(crypto.HashString("email:jelle@vandenhooff.name"), 0)
		bytes, _ := json.MarshalIndent(history, "", "  ")
		w.Write(bytes)
	})

	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		status := &Status{
			PublicKey:  s.config.PublicKey,
			Upstream:   s.config.Upstream,
			TotalNodes: s.dedup.NumNodes(),
		}

		bytes, _ := json.MarshalIndent(status, "", "  ")
		w.Write(bytes)
	})

	http.Serve(socket, http.DefaultServeMux)
	/*
		http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
		http.Handle("/dkim/", http.StripPrefix("/dkim", runDKIMServer()))
		go http.Serve(socket, nil)
	*/
}
