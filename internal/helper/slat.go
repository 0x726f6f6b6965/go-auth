package helper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
)

var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

type Salt struct {
	saltByte   []byte
	SaltString string
}

// create salt
func CreateNewSalt() *Salt {
	secret := make([]byte, 32)
	_, _ = rand.Reader.Read(secret)
	str := b32NoPadding.EncodeToString(secret)
	return &Salt{
		saltByte:   secret,
		SaltString: str,
	}
}

// create salt based on string
func CreateSaltByString(salt string) (*Salt, error) {
	b, err := b32NoPadding.DecodeString(salt)
	if err != nil {
		return &Salt{}, err
	}
	return &Salt{saltByte: b, SaltString: salt}, nil
}

func (s *Salt) SaltInput(in string) (string, error) {
	h := sha256.New()
	_, err := h.Write(s.saltByte)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum([]byte(in))), nil
}
