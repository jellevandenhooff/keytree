package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jellevandenhooff/keytree/crypto"
)

const configName = "keytree-server.config"
const databaseName = "keytree-server.boltdb"

var dataDir = flag.String("data-dir", "data", "Where to keep data.")
var listenAddr = flag.String("listenAddr", ":8000", "Address to listen on.")

var catchUpRecoveryString = flag.String("catch-up-recovery", "", "Run Keytree in recovery mode allowing keys up to `catch-up-recovery` time old. Format should be a floating-point number followed by a single character indicating 'h'ours, 'd'ays, 'm'onths, or 'y'ears.")

var catchUpRecoveryEnabled bool
var catchUpRecoveryCutoff uint64

const updateFlushInterval = 50 * time.Millisecond
const noFlushUpdateInterval = 10 * time.Second
const updateBatchBacklog = 200

const fixerParallelism = 8

const updateQueueSize = 1000
const reconcileQueueSize = 2000

type ServerInfo struct {
	Address   string
	PublicKey string
}

type Config struct {
	PublicKey  string
	PrivateKey string
	Upstream   []ServerInfo
	DNSServer  string
}

func parseDuration(duration string) (uint64, error) {
	if len(duration) < 1 {
		return 0, errors.New("missing suffix")
	}

	var suffix string
	duration, suffix = duration[:len(duration)-1], duration[len(duration)-1:]
	var multiplier float64

	switch suffix {
	case "h":
		multiplier = 60 * 60
	case "d":
		multiplier = 24 * 60 * 60
	case "m":
		multiplier = 31 * 24 * 60 * 60
	case "y":
		multiplier = 365 * 24 * 60 * 60
	default:
		return 0, errors.New("unknown suffix character")
	}

	n, err := strconv.ParseFloat(duration, 64)
	if err != nil {
		return 0, err
	}

	return uint64(n * multiplier), nil
}

func parseFlags() {
	flag.Parse()

	if *catchUpRecoveryString == "" {
		catchUpRecoveryEnabled = false
	} else {
		catchUpRecoveryEnabled = true

		cutoff, err := parseDuration(*catchUpRecoveryString)
		if err != nil {
			log.Panicf("error parsing cutoff: %s\n", err)
		}

		catchUpRecoveryCutoff = cutoff
	}
}

func writeDefaultConfig(path string) error {
	publicKey, privateKey := crypto.GenerateRandomEd25519Keypair()
	bytes, err := json.MarshalIndent(&Config{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		DNSServer:  "8.8.4.4:53",
	}, "", "  ")

	if err != nil {
		return fmt.Errorf("couldn't marshal config: %s", err)
	}
	if err := ioutil.WriteFile(path, bytes, 0600); err != nil {
		return fmt.Errorf("couldn't write config: %s", err)
	}

	return nil
}

func loadConfig(path string) (*Config, *crypto.Signer, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := writeDefaultConfig(path); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't read config: %s", err)
	}
	var config *Config
	if err := json.Unmarshal(bytes, &config); err != nil {
		return nil, nil, fmt.Errorf("couldn't unmarshal config: %s", err)
	}
	signer, err := crypto.NewSigner(config.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return config, signer, nil
}
