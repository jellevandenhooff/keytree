package wire

import (
	"encoding/json"
	"net/http"
)

func ReplyJSON(w http.ResponseWriter, v interface{}) {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}
