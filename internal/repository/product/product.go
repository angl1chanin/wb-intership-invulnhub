package product

import (
	"database/sql"
	"errors"
	"fmt"
	"wb-vulnhub/internal/entity"
	"wb-vulnhub/internal/repository"
)

type productRepository struct {
	db *sql.DB
}

// checking for compliance of the methods of the model and its interface
var _ repository.ProductRepository = (*productRepository)(nil)

func New(db *sql.DB) (*productRepository, error) {
	const op = "vulnerable.internal.repository.product_repository.NewProductRepository"

	queries := []string{
		`CREATE TABLE Products (
			id INTEGER PRIMARY KEY,
			name VARCHAR(255),
			description TEXT,
			price INT
        );`,
		`CREATE TABLE flags (
		  	id INTEGER PRIMARY KEY ,
		  	flag TEXT
		);`,
		`INSERT INTO Products (name, description, price) VALUES 
			('Product 1', 'This is product 1', 100),
			('Product 2', 'This is product 2', 200),
			('Product 3', 'This is product 3', 300),
			('Product 4', 'This is product 4', 400),
			('Product 5', 'This is product 5', 500),
			('Product 6', 'This is product 6', 600),
			('Product 7', 'This is product 7', 700),
			('Product 8', 'This is product 8', 800),
			('Product 9', 'This is product 9', 900),
			('Product 10', 'This is product 10', 1000),
			('Product 11', 'This is product 11', 1100),
			('Product 12', 'This is product 12', 1200),
			('Product 13', 'This is product 13', 1300),
			('Product 14', 'This is product 14', 1400),
			('Product 15', 'This is product 15', 1500);
		`,
		`INSERT INTO flags (flag) VALUES 
			('fake flag'),
			('WB{n1c3_tr9_y0u_w1n}');
		`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			fmt.Errorf("%s: %w", op, err)
		}
	}

	return &productRepository{db: db}, nil
}

func (r *productRepository) GetByIdVulnerable(id string) (*entity.Product, error) {
	const op = "vulnerable.internal.repository.product_repository.GetByIdVulnerable"

	stmt := `SELECT id, description FROM Products WHERE id = ` + id

	product := &entity.Product{}

	err := r.db.QueryRow(stmt).Scan(&product.ID, &product.Name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", "No rows returned", err)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return product, nil
}
