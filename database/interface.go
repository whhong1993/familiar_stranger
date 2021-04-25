package database

import "github.com/jinzhu/gorm"

type Database interface {
	Open(dbType string, con string) (db *gorm.DB, err error)
	GetConnect() string
}
