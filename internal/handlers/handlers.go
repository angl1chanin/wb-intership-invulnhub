package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"html"
	"html/template"
	"io/ioutil"
	"net/http"
	"os/exec"
	"strconv"
	"wb-vulnhub/internal/entity"
	"wb-vulnhub/internal/repository"
)

type handlers struct {
	productRepo repository.ProductRepository
	noteRepo    repository.NoteRepository
}

func New(productRepo repository.ProductRepository, noteRepo repository.NoteRepository) *handlers {
	return &handlers{
		productRepo: productRepo,
		noteRepo:    noteRepo,
	}
}

func (h *handlers) Home(w http.ResponseWriter, r *http.Request) {
	files := []string{
		"./web/ui/html/base.layout.tmpl",
		"./web/ui/html/pages/main.page.tmpl",
	}

	tmpl, err := template.New("main.page.tmpl").ParseFiles(files...)
	if err != nil {
		panic(err)
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		panic(err)
	}
}

func (h *handlers) XSS(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	tmpl := "<a href='/'>Home</a><br>"

	if len(username) == 0 {
		tmpl += "<p>Send get parameter 'username'</p>"
	} else {
		tmpl += "<p>Your username: " + html.EscapeString(username) + "</p>"
	}

	w.Write([]byte(tmpl))
}

func (h *handlers) SQLi(w http.ResponseWriter, r *http.Request) {
	files := []string{
		"./web/ui/html/base.layout.tmpl",
		"./web/ui/html/pages/sqli.page.tmpl",
	}

	tmpl, err := template.New("sqli.page.tmpl").ParseFiles(files...)
	if err != nil {
		panic(err)
	}

	// POST method
	if r.Method == http.MethodPost {
		const op = "vulnerable.internal.handlers.handlers.SQLi.POST"

		r.ParseForm()
		id := r.FormValue("id")

		item, err := h.productRepo.GetByIdVulnerable(id)
		if err != nil {
			fmt.Errorf("%s: %w", op, err)
		}

		if item == nil {
			item = &entity.Product{}
		}

		content := &struct {
			Query string
			Item  entity.Product
			Err   error
		}{
			Query: "SELECT id, description FROM Products WHERE id = " + id,
			Item:  *item,
			Err:   err,
		}

		err = tmpl.Execute(w, content)
		if err != nil {
			fmt.Errorf("%s: %w", op, err)
		}

		return
	}

	// GET method
	if r.Method == http.MethodGet {
		const op = "vulnerable.internal.handlers.handlers.SQLi.GET"
		content := &struct {
			Query string
		}{
			Query: "SELECT id, description FROM Products WHERE id = ?",
		}

		err = tmpl.Execute(w, content)
		if err != nil {
			fmt.Errorf("%s: %w", op, err)
		}
	}
}

func (h *handlers) IDOR(w http.ResponseWriter, r *http.Request) {
	const op = "vulnerable.internal.handlers.handlers.IDOR"

	files := []string{
		"./web/ui/html/base.layout.tmpl",
		"./web/ui/html/pages/idor.page.tmpl",
	}

	tmpl, err := template.New("idor.page.tmpl").ParseFiles(files...)
	if err != nil {
		panic(err)
	}

	var message string
	var notes []entity.Note

	id := r.URL.Query().Get("id")
	if len(id) > 0 {
		note, err := h.noteRepo.GetById(id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fmt.Errorf("%s: %w", op, err)
		}
		notes = append(notes, *note)
	} else {
		notes, err = h.noteRepo.GetLimited()
		if err != nil {
			fmt.Errorf("%s: %w", op, err)
		}
	}

	intId, _ := strconv.Atoi(id)

	content := &struct {
		Id      int
		Message string
		Notes   []entity.Note
	}{
		Id:      intId,
		Message: message,
		Notes:   notes,
	}

	err = tmpl.Execute(w, content)
	if err != nil {
		panic(err)
	}
}

func (h *handlers) CommandInjection(w http.ResponseWriter, r *http.Request) {
	const op = "vulnerable.internal.handlers.handlers.CommandInjection"

	files := []string{
		"./web/ui/html/base.layout.tmpl",
		"./web/ui/html/pages/commandinj.page.tmpl",
	}

	tmpl, err := template.New("commandinj.page.tmpl").ParseFiles(files...)
	if err != nil {
		panic(err)
	}

	ip := r.URL.Query().Get("ip")

	out := []byte{0}
	command := "ping -c 1 "

	if len(ip) != 0 {
		command += ip
		cmd := exec.Command("sh", "-c", command)
		out, err = cmd.Output()
		if err != nil {
			fmt.Printf("%s: %w", op, err)
		}
	}

	content := &struct {
		Ip      string
		Out     string
		Command string
	}{
		Ip:      ip,
		Out:     string(out),
		Command: command,
	}

	err = tmpl.Execute(w, content)
	if err != nil {
		panic(err)
	}
}

func (h *handlers) PathTraversal(w http.ResponseWriter, r *http.Request) {
	files := []string{
		"./web/ui/html/base.layout.tmpl",
		"./web/ui/html/pages/pathtraversal.page.tmpl",
	}

	tmpl, err := template.New("pathtraversal.page.tmpl").ParseFiles(files...)
	if err != nil {
		panic(err)
	}

	message := ""
	data := []byte{}

	file := r.URL.Query().Get("file")
	if len(file) > 0 {
		data, err = ioutil.ReadFile(file)
		if err != nil {
			message = err.Error()
		}
		w.Write(data)
	}

	content := &struct {
		Message string
	}{
		Message: message,
	}

	err = tmpl.Execute(w, content)
	if err != nil {
		panic(err)
	}
}

func (h *handlers) BruteForce(w http.ResponseWriter, r *http.Request) {
	files := []string{
		"./web/ui/html/base.layout.tmpl",
		"./web/ui/html/pages/bruteforce.page.tmpl",
	}

	tmpl, err := template.New("bruteforce.page.tmpl").ParseFiles(files...)
	if err != nil {
		panic(err)
	}

	if r.Method == http.MethodPost {
		var correctPassword = "password123"

		r.ParseForm()
		password := r.Form.Get("password")

		var message = ""
		var loggedIn bool
		if password == correctPassword {
			message = "Login successful"
			loggedIn = true
		} else {
			message = "Login failed"
			loggedIn = false
		}

		content := &struct {
			Message  string
			LoggedIn bool
		}{
			Message:  message,
			LoggedIn: loggedIn,
		}

		err = tmpl.Execute(w, content)
		if err != nil {
			panic(err)
		}
	}

	// get request
	if r.Method == http.MethodGet {
		err = tmpl.Execute(w, nil)
		if err != nil {
			panic(err)
		}
	}
}
