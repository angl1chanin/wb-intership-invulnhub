package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"github.com/steambap/captcha"
	"html"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"wb-vulnhub/internal/entity"
	"wb-vulnhub/internal/repository"
)

type handlers struct {
	productRepo repository.ProductRepository
	noteRepo    repository.NoteRepository
}

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte("HFUIHIUFWHQNKJN1024*@&$*(N!DH!@DH")
	store = sessions.NewCookieStore(key)
)

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
		const op = "invulnerable.internal.handlers.handlers.SQLi.POST"

		var item *entity.Product

		r.ParseForm()
		id := r.FormValue("id")
		intID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			fmt.Errorf("%s: %w", op, err)
		} else {
			item, err = h.productRepo.GetByIdInvulnerable(intID)
			if err != nil {
				fmt.Errorf("%s: %w", op, err)
			}
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
		const op = "invulnerable.internal.handlers.handlers.SQLi.GET"
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
	const op = "invulnerable.internal.handlers.handlers.IDOR"

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
	user := r.URL.Query().Get("user")
	if len(id) > 0 {
		note, err := h.noteRepo.GetById(id, user)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fmt.Errorf("%s: %w", op, err)
		}
		notes = append(notes, *note)
	} else {
		notes, err = h.noteRepo.GetByUser(user)
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
	const op = "invulnerable.internal.handlers.handlers.CommandInjection"

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
		cmd := exec.Command("ping", "-c", "1", ip)
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

	err = tmpl.Execute(w, nil)
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
		session, _ := store.Get(r, "session")

		r.ParseForm()
		password := r.Form.Get("password")
		capText := r.Form.Get("captcha")

		var message = ""
		var loggedIn bool

		correctCaptcha, ok := session.Values["captcha"].(string)
		if !ok {
			fmt.Println(ok)
			return
		}

		if capText != correctCaptcha {
			message = "Captcha is incorrect"
			loggedIn = false
		} else {
			if password == correctPassword {
				message = "Login successful"
				loggedIn = true
			} else {
				message = "Login failed"
				loggedIn = false
			}
		}

		content := &struct {
			Message  string
			LoggedIn bool
		}{
			Message:  message,
			LoggedIn: loggedIn,
		}

		// this code the same that in the get method, it is just rewrite captcha in session and image
		// i really like DRY pattern, but not in this case :)

		// create a captcha of 150x50px
		data, _ := captcha.New(150, 50)

		session.Values["captcha"] = data.Text
		session.Save(r, w)

		// Create a file
		f, err := os.Create("./web/ui/static/captcha.png")
		if err != nil {
			panic(err)
		}
		defer f.Close()

		// Write the image to the file
		data.WriteImage(f)

		err = tmpl.Execute(w, content)
		if err != nil {
			panic(err)
		}
	}

	// get request
	if r.Method == http.MethodGet {
		session, _ := store.New(r, "session")
		// create a captcha of 150x50px
		data, _ := captcha.New(150, 50)

		session.Values["captcha"] = data.Text
		session.Save(r, w)

		// Create a file
		f, err := os.Create("./web/ui/static/captcha.png")
		if err != nil {
			panic(err)
		}
		defer f.Close()

		// Write the image to the file
		data.WriteImage(f)

		err = tmpl.Execute(w, nil)
		if err != nil {
			panic(err)
		}
	}
}
