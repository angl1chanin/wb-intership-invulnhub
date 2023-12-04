package app

import (
	"database/sql"
	"fmt"
	"net/http"
	"wb-vulnhub/internal/handlers"
	"wb-vulnhub/internal/logger"
	"wb-vulnhub/internal/repository/note"
	"wb-vulnhub/internal/repository/product"
)

func Run() {
	// open db connection
	db, err := sql.Open("sqlite3", "./storage.db")
	if err != nil {
		fmt.Errorf("%w", err)
	}

	// init repositories
	product, err := product.New(db)
	if err != nil {
		fmt.Errorf("%w", err)
	}

	note, err := note.New(db)
	if err != nil {
		fmt.Errorf("%w", err)
	}

	// init handlers
	h := handlers.New(product, note)

	// init router
	mux := http.NewServeMux()

	// file server
	fs := http.FileServer(http.Dir("./web/ui/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// init routes
	mux.HandleFunc("/", h.Home)
	mux.HandleFunc("/xss", h.XSS)
	mux.HandleFunc("/sqli", h.SQLi)
	mux.HandleFunc("/idor", h.IDOR)
	mux.HandleFunc("/command-inj", h.CommandInjection)
	mux.HandleFunc("/path-traversal", h.PathTraversal)
	mux.HandleFunc("/brute-force", h.BruteForce)

	log := logger.New(mux)

	err = http.ListenAndServe(":3333", log)
	if err != nil {
		fmt.Println("Error when start: ", err)
	}
}
