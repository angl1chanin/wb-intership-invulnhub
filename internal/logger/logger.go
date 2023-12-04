package logger

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type Logger struct {
	handler http.Handler
}

func New(handler http.Handler) *Logger {
	return &Logger{handler: handler}
}

func (l *Logger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//start := time.Now()
	//l.handler.ServeHTTP(w, r)
	//log.Printf("%s %s %v", r.Method, r.URL.Path, time.Since(start))
	start := time.Now()

	// Read the request body
	var bodyBytes []byte
	if r.Body != nil {
		// Read the body into a buffer
		bodyBytes, _ = ioutil.ReadAll(r.Body)
		// Restore the io.ReadCloser to its original state
		r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	l.handler.ServeHTTP(w, r)

	log.Printf("%s %s %s %v", r.Method, r.URL.Path, string(bodyBytes), time.Since(start))
}
