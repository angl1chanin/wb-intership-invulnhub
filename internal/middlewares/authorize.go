package middlewares

import (
	"net/http"
	"wb-vulnhub/internal/repository"
)

func CheckOwner(repo repository.NoteRepository, next http.Handler) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// get GET params
		user := r.URL.Query().Get("user")
		password := r.URL.Query().Get("password")

		// check if it's contain smth
		if len(user) == 0 || len(password) == 0 {
			http.Error(w, "User and password are required", http.StatusBadRequest)
			return
		}

		if ok, err := repo.IsUserExists(user); err != nil || !ok {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		if ok, err := repo.IsValidPassword(user, password); err != nil || !ok {
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}
