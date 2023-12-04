package repository

import "wb-vulnhub/internal/entity"

type ProductRepository interface {
	GetByIdInvulnerable(id int64) (*entity.Product, error)
}

type NoteRepository interface {
	GetById(id, user string) (*entity.Note, error)
	GetLimited() ([]entity.Note, error)
	IsOwner(id int, user string) (bool, error)
	IsValidPassword(user, password string) (bool, error)
	IsUserExists(user string) (bool, error)
	GetByUser(user string) ([]entity.Note, error)
}
