package dkimproof

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jellevandenhooff/dkim"
	"github.com/jellevandenhooff/smtp"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/unixtime"
	"github.com/jellevandenhooff/keytree/wire"
)

type Server struct {
	mu        sync.Mutex
	domain    string
	pending   map[string]*wire.DKIMUpdate
	dnsClient dkim.DNSClient
}

func (s *Server) cleanOldPending() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, v := range s.pending {
		if v.Expiration < unixtime.Now() {
			delete(s.pending, k)
		}
	}
}

func (s *Server) run() {
	for {
		s.cleanOldPending()
		time.Sleep(10 * time.Second)
	}
}

func (s *Server) handleMail(m *smtp.Mail) {
	/*
		mail_id := base32.EncodeToString(crypto.HashString(m.Mail).Bytes()[:8])
		if err := ioutil.WriteFile(filepath.Join("received-emails", mail_id), []byte(m.Mail), 0644); err != nil {
			log.Printf("could not store email: %s\n", err)
		}
	*/

	// Hold on to err for later reporting
	verified, err := dkim.ParseAndVerify(m.Mail, dkim.HeadersOnly, s.dnsClient)

	s.mu.Lock()
	defer s.mu.Unlock()

	update := s.pending[strings.ToLower(m.To)]
	if update == nil {
		return
	}

	if err == nil {
		err = CheckVerifiedEmail(verified, update.Statement)
	}

	if err != nil {
		update.Status = append(update.Status, fmt.Sprintf("%s", err.Error()))
		// update.Status = append(update.Status, fmt.Sprintf("%s (%s)", err.Error(), mail_id))
		return
	}

	update.Proof = verified.CanonHeaders()
}

func replyJSON(w http.ResponseWriter, v interface{}) {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}

func (s *Server) handlePrepare(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var req wire.DKIMStatement
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := req.Check(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	email := crypto.GenerateRandomToken(6) + "@" + s.domain
	s.pending[email] = &wire.DKIMUpdate{
		Statement:  &req,
		Proof:      "",
		Status:     nil,
		Expiration: unixtime.Now() + 15*60,
	}

	replyJSON(w, email)
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	s.mu.Lock()
	defer s.mu.Unlock()

	update, found := s.pending[r.URL.Query().Get("email")]
	if !found {
		http.NotFound(w, r)
	}

	replyJSON(w, &wire.DKIMStatus{
		Proof:      update.Proof,
		Status:     update.Status,
		Expiration: update.Expiration,
	})
}

func RunServer(domain string, dnsClient dkim.DNSClient) (*Server, error) {
	s := &Server{
		domain:    domain,
		pending:   make(map[string]*wire.DKIMUpdate),
		dnsClient: dnsClient,
	}

	l, err := net.Listen("tcp", ":smtp")
	if err != nil {
		return nil, err
	}

	go smtp.Serve(domain, l, func(m *smtp.Mail) {
		s.handleMail(m)
	})

	go s.run()
	return s, nil
}

func (s *Server) AddHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/dkim/prepare", func(w http.ResponseWriter, r *http.Request) {
		s.handlePrepare(w, r)
	})
	mux.HandleFunc("/dkim/poll", func(w http.ResponseWriter, r *http.Request) {
		s.handlePoll(w, r)
	})
}
