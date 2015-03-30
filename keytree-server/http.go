package main

/*
	// const maxEntriesPerDump = 5000

	http.HandleFunc("/lookup/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")

		state := srv.state.Load().(*state)

		name := strings.TrimPrefix(r.URL.Path, "/lookup/")
		hash := crypto.HashString(name)

		lookup, entry := state.trie.Lookup(hash)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]rpc.Result{{
			Entry:  entry,
			Lookup: lookup,
		}})

		lookups.Add(1)
	})
	http.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")

		var update *keytree.Update
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := srv.doUpdate(update); err != nil {
			// todo: distinguish between internal server error and bad request?
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		updateStats.Add("Direct", 1)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(nil)

	})

	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")

		state := srv.state.Load().(*state)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(state.status)
	})

	http.HandleFunc("/dump", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")

		state := srv.state.Load().(*state)

		version := state.version

		versionString := r.URL.Query().Get("version")
		if versionString != "" {
			versionInt, err := strconv.Atoi(versionString)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if versionInt < 0 || uint64(versionInt) > state.version {
				http.Error(w, "version out of range", http.StatusBadRequest)
				return
			}
			version = uint64(versionInt)
		}

		first := crypto.EmptyHash

		firstString := r.URL.Query().Get("first")
		if firstString != "" {
			first, err = crypto.FromString(firstString)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		dump := rpc.Dump{
			Entries: make(map[string]*keytree.Entry),
			Version: version,
		}

		versionBytes := encoding.EncodeBEUint64(version)

		if err := db.View(func(tx *bolt.Tx) error {
			entries := tx.Bucket([]byte("entries"))

			c := entries.Cursor()
			for k, _ := c.Seek(first.Bytes()); k != nil; k, _ = c.Next() {
				c := entries.Bucket(k).Cursor()
				c.Seek(versionBytes)
				_, v := c.Prev()
				if v == nil {
					continue
				}

				var entry *keytree.Entry
				if err := json.Unmarshal(v, &entry); err != nil {
					return err
				}

				dump.Entries[entry.NameHash().String()] = entry
				if len(dump.Entries) >= maxEntriesPerDump {
					break
				}
			}

			return nil
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(dump)
	})

	http.Handle("/updates", websocket.Handler(func(conn *websocket.Conn) {
		state := srv.state.Load().(*state)

		versionInt, err := strconv.Atoi(conn.Request().URL.Query().Get("version"))
		if err != nil {
			return
		}
		if versionInt < 0 || uint64(versionInt) > state.version {
			return
		}
		version := uint64(versionInt)

		state = nil // let GC collect state

		srv.broadcastLock.Lock()

		if err := db.View(func(tx *bolt.Tx) error {
			entries := tx.Bucket([]byte("updates"))

			c := entries.Cursor()
			for k, v := c.Seek(encoding.EncodeBEUint64(version)); k != nil; k, v = c.Next() {
				version := encoding.DecodeBEUint64(k)
				if version > srv.broadcastVersion {
					break
				}

				var update *keytree.Update
				if err := json.Unmarshal(v, &update); err != nil {
					return err
				}
				if err := websocket.JSON.Send(conn, update); err != nil {
					return err
				}
			}

			return nil
		}); err != nil {
			srv.broadcastLock.Unlock()
			conn.Close()
			log.Printf("error reading updates: %s\n", err)
			return
		}

		srv.broadcastConnections = append(srv.broadcastConnections, conn)
		srv.broadcastLock.Unlock()

		// block on an open connection
		conn.Read(nil)
	}))
*/
