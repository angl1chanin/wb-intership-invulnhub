package note

import (
	"database/sql"
	"fmt"
	"wb-vulnhub/internal/entity"
	"wb-vulnhub/internal/repository"
)

type noteRepository struct {
	db *sql.DB
}

// checking for compliance of the methods of the model and its interface
var _ repository.NoteRepository = (*noteRepository)(nil)

func New(db *sql.DB) (*noteRepository, error) {
	const op = "invulnerable.internal.repository.note.New"

	queries := []string{
		`
			CREATE TABLE IF NOT EXISTS notes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			description TEXT,
			user TEXT NOT NULL,
			password VARCHAR(255) NOT NULL
		);
		`,
		`
			INSERT INTO notes (title, description, user, password) VALUES 
			   ('Amazing work', 'Find better', 'user', '1234'),
			   ('Almost done', 'Try again', 'user', '1234'),
			   ('It is easy idor', 'Y r close', 'user', '1234');
		`,
		`
			INSERT INTO notes (id, title, description, user, password) VALUES (1337, 'flag', 'WB{s1m51e_1d0r}', 'admin', 'admin');
		`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			fmt.Errorf("%s: %w", op, err)
		}
	}

	return &noteRepository{db: db}, nil
}

func (r *noteRepository) GetById(id, user string) (*entity.Note, error) {
	const op = "invulnerable.internal.repository.note.Create"

	note := &entity.Note{}

	err := r.db.QueryRow(`SELECT id, title, description FROM notes WHERE id = ? AND user = ?`, id, user).Scan(&note.ID, &note.Title, &note.Description)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return note, nil
}

func (r *noteRepository) GetLimited() ([]entity.Note, error) {
	const op = "invulnerable.internal.repository.note.GetLimited"

	rows, err := r.db.Query(`SELECT * FROM notes LIMIT 3 OFFSET 0`)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	defer rows.Close()

	var notes []entity.Note

	for rows.Next() {
		note := entity.Note{}
		err := rows.Scan(&note.ID, &note.Title, &note.Description)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}

		notes = append(notes, note)
	}

	return notes, nil
}

func (r *noteRepository) IsOwner(id int, user string) (bool, error) {
	const op = "invulnerable.internal.repository.note.isOwner"

	var owner string

	err := r.db.QueryRow(`SELECT user FROM notes WHERE id = ?`, id).Scan(&owner)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return owner == user, nil
}

func (r *noteRepository) IsValidPassword(user, password string) (bool, error) {
	const op = "invulnerable.internal.repository.note.isValidPassword"

	var dbPassword string

	err := r.db.QueryRow(`SELECT password FROM notes WHERE user = ? LIMIT 1 OFFSET 0`, user).Scan(&dbPassword)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return dbPassword == password, nil
}

func (r *noteRepository) IsUserExists(user string) (bool, error) {
	var count int

	err := r.db.QueryRow("SELECT COUNT(*) FROM notes WHERE user = ?", user).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (r *noteRepository) GetByUser(user string) ([]entity.Note, error) {
	rows, err := r.db.Query("SELECT title, description FROM notes WHERE user = ?", user)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var notes []entity.Note
	for rows.Next() {
		var note entity.Note
		err := rows.Scan(&note.Title, &note.Description)
		if err != nil {
			return nil, err
		}
		notes = append(notes, note)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return notes, nil
}