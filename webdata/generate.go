package webdata

//go:generate go-bindata-assetfs -pkg=webdata -prefix=../ ../web ../web/dist

import (
	"net/http"
)

func FileServer() http.Handler {
	return http.FileServer(assetFS())
}
