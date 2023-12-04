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
	const op = "vulnerable.internal.repository.note.New"

	queries := []string{
		`
			CREATE TABLE IF NOT EXISTS notes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			description TEXT
		);
		`,
		`
			INSERT INTO notes (title, description) VALUES 
			   ('Amazing work', 'Find better'),
			   ('Almost done', 'Try again'),
			   ('It is easy idor', 'Y r close');
		`,
		`
			INSERT INTO notes (id, title, description) VALUES (1337, 'flag', 'WB{s1m51e_1d0r}');
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

func (r *noteRepository) GetById(id string) (*entity.Note, error) {
	const op = "vulnerable.internal.repository.note.Create"

	note := &entity.Note{}

	err := r.db.QueryRow(`SELECT * FROM notes WHERE id = ?`, id).Scan(&note.ID, &note.Title, &note.Description)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return note, nil
}

func (r *noteRepository) GetLimited() ([]entity.Note, error) {
	const op = "vulnerable.internal.repository.note.GetLimited"

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
