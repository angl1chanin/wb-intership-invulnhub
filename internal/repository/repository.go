package repository

import "wb-vulnhub/internal/entity"

type ProductRepository interface {
	GetByIdVulnerable(id string) (*entity.Product, error)
}

type NoteRepository interface {
	GetById(id string) (*entity.Note, error)
	GetLimited() ([]entity.Note, error)
}
