package repository

import "wb-vulnhub/internal/entity"

type ProductRepository interface {
	GetByIdInvulnerable(id int64) (*entity.Product, error)
}

type NoteRepository interface {
	GetById(id string) (*entity.Note, error)
	GetLimited() ([]entity.Note, error)
}
