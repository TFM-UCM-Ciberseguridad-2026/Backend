package domain

import "errors"

var (
	ErrNodeAlreadyExists = errors.New("node already exists, save ignored")
	ErrNodeNotFound      = errors.New("node not found, update ignored")
)
