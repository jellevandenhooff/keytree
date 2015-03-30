package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/rpc"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/dkimproof"
	"github.com/jellevandenhooff/keytree/dns"
	"github.com/jellevandenhooff/keytree/encoding/base32"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/unixtime"
	"github.com/jellevandenhooff/keytree/wire"
)

var server = flag.String("server", "localhost:8000", "URL of Keytree server")

func usage() {
	fmt.Printf("Usage: %s [flags] <name> [key=value]...\nFlags:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	publicKeys := []string{
		//"ed25519-pub(xmmqz7cvgdd9ewa79vw9cw9qvemyd4x3zsaftacc2jqqm4nfzw20)",
		"ed25519-pub(26wj522ncyprkc0t9yr1e1cz2szempbddkay02qqqxqkjnkbnygg)",
	}

	dnsClient := &dns.SimpleDNSClient{
		Server: "8.8.4.4:53",
	}

	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}
	name := flag.Arg(0)
	if !strings.HasPrefix(name, "email:") && !strings.HasPrefix(name, "test:") {
		name = "email:" + name
	}

	client, err := rpc.DialHTTP("tcp", *server)
	if err != nil {
		log.Panicln(err)
	}
	defer client.Close()
	conn := wire.NewKeyTreeClient(client)

	newKeys := make(map[string]string)
	for _, arg := range flag.Args()[1:] {
		idx := strings.Index(arg, "=")
		if idx == -1 {
			usage()
			os.Exit(1)
		}
		if arg[:idx] == "keytree:recovery" {
			fmt.Println("This commandline tool does not let you manually manage your lock key. Managing your lock key is tricky business -- if you want to take care of your lock key by hand, modifying this tool should be a piece of cake!")
			os.Exit(1)
		}
		newKeys[arg[:idx]] = arg[idx+1:]
	}

	fmt.Printf("Updating Keytree record for '%s'.\n", name)

	var old *wire.Entry

	{
		reply, err := conn.Lookup(&wire.LookupRequest{
			Hash:       crypto.HashString(name),
			PublicKeys: publicKeys,
		})
		if err != nil {
			log.Panicln(err)
		}

		var checkedSignatures []string

		for _, publicKey := range publicKeys {
			signedTrieLookup, found := reply.SignedTrieLookups[publicKey]
			if !found {
				log.Panicln("lookup missing")
			}

			signedRoot := signedTrieLookup.SignedRoot

			if err := crypto.Verify(publicKey, signedRoot.Root, signedRoot.Signature); err != nil {
				log.Panicln(err)
			}

			if signedRoot.Root.Timestamp < unixtime.Now()-20 || signedRoot.Root.Timestamp > unixtime.Now()+20 {
				log.Panicln("signature time out of range!")
			}

			rootHash := trie.CompleteLookup(signedTrieLookup.TrieLookup, crypto.HashString(name), reply.Entry.Hash())

			if rootHash != signedRoot.Root.RootHash {
				log.Panicln("lookup does not match signed root")
			}

			checkedSignatures = append(checkedSignatures, publicKey)
		}

		old = reply.Entry
	}

	newEntry := &wire.Entry{
		Name:       name,
		Keys:       make(map[string]string),
		Timestamp:  unixtime.Now() - 10, // build in some slack if our clock is ahead
		InRecovery: false,
	}

	var oldPublic, oldPrivate string
	if old != nil && old.Keys["keytree:recovery"] != "" {
		fmt.Printf("This Keytree record is currently locked. Please enter the password used to lock this Keytree record to update it: ")
		pwbytes, _ := terminal.ReadPassword(syscall.Stdin)
		fmt.Println()
		password := string(pwbytes)
		oldPublic, oldPrivate = crypto.GenerateEd25519KeypairFromSecret(password, name)
		if oldPublic != old.Keys["keytree:recovery"] {
			fmt.Printf("Incorrect password.\n")
			os.Exit(1)
		}
	}

	var newPublic string
	fmt.Printf("Enter a password to lock your Keytree record, or leave empty for no lock: ")
	pwbytes, _ := terminal.ReadPassword(syscall.Stdin)
	fmt.Println()
	password := string(pwbytes)

	if password != "" {
		fmt.Printf("Please repeat the password: ")
		repeated, _ := terminal.ReadPassword(syscall.Stdin)
		fmt.Println()
		if password != string(repeated) {
			fmt.Printf("Passwords did not match!\n")
			os.Exit(1)
		}
		newPublic, _ = crypto.GenerateEd25519KeypairFromSecret(password, name)
	}

	if old != nil {
		for k, v := range old.Keys {
			newEntry.Keys[k] = v
		}
	}
	for k, v := range newKeys {
		if v == "" {
			delete(newEntry.Keys, k)
		} else {
			newEntry.Keys[k] = v
		}
	}

	if newPublic == "" {
		delete(newEntry.Keys, "keytree:recovery")
	} else {
		newEntry.Keys["keytree:recovery"] = newPublic
	}

	signatures := make(map[string]string)
	if oldPublic != "" {
		signatures[oldPublic], _ = crypto.Sign(oldPrivate, newEntry)
	}

	if len(signatures) == 0 {
		if strings.HasPrefix(name, "email:") {
			statement := &wire.DKIMStatement{
				Sender: strings.TrimPrefix(name, "email:"),
				Token:  base32.EncodeToString(newEntry.Hash().Bytes()),
			}

			dkimConn := wire.NewDKIMClient(client)

			fmt.Printf("Obtaining DKIM proof for new entry...\n")
			buffer := bytes.NewBuffer(nil)
			json.NewEncoder(buffer).Encode(&statement)

			reply, err := dkimConn.DKIMPrepare(&wire.DKIMPrepareRequest{
				Statement: statement,
			})
			if err != nil {
				log.Panicln(err)
			}

			email := reply.Email

			if err := exec.Command("/usr/bin/open", fmt.Sprintf("mailto:%s?subject=%s", email, statement.Token)).Run(); err != nil {
				fmt.Printf("To verify e-mail ownership, send an e-mail to %s with subject %s.\n", email, statement.Token)
			}

			fmt.Printf("Waiting for e-mail...\n")

			idx := 0
			proof := ""
			for proof == "" {
				time.Sleep(1 * time.Second)

				reply, err := dkimConn.DKIMPoll(&wire.DKIMPollRequest{
					Email: email,
				})
				if err != nil {
					log.Panicln(err)
				}

				for ; idx < len(reply.Status); idx++ {
					fmt.Printf("%s\n", reply.Status[idx])
				}

				proof = reply.Proof
			}

			if err := dkimproof.CheckPlainEmail(proof, statement, dnsClient); err != nil {
				fmt.Printf("Got a DKIM proof from the server that we can't verify: %s\n", err)
				os.Exit(1)
			}

			signatures["dkim"] = proof
		}
	}

	{
		fmt.Printf("Submitting update to Keytree server...\n")
		_, err := conn.Update(&wire.UpdateRequest{
			SignedEntry: &wire.SignedEntry{
				Entry:      newEntry,
				Signatures: signatures,
			},
		})
		if err != nil {
			log.Panicln(err)
		}
	}

	/*
		buffer := bytes.NewBuffer(nil)
		json.NewEncoder(buffer).Encode(&update)
		var res interface{}
		resp, err = http.Post(*server+"/submit", "text/json; charset=utf8", buffer)
		parse(resp, err, "submitting update", &res)
	*/

	fmt.Printf("Successfully applied update.\n")

	if newPublic == "" {
		fmt.Printf("Your Keytree record is valid, but unlocked, so the owner of your domain can change your record at any time.\n")
	} else {
		fmt.Printf("Your Keytree record is valid. To ensure your Keytree record stays secure, make sure to update your record daily.\n")
	}
}
