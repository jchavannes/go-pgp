package pgp

import (
	"golang.org/x/crypto/openpgp"
	"bytes"
	"fmt"
	"io"
	"golang.org/x/crypto/openpgp/armor"
	"compress/gzip"
	_ "crypto/sha256"
	_ "golang.org/x/crypto/ripemd160"
)

func Encrypt(entity *openpgp.Entity, message []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, "Message", make(map[string]string))
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating OpenPGP armor: %v", err)
	}

	plain, err := openpgp.Encrypt(w, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating entity for encryption: %v", err)
	}

	compressed, err := gzip.NewWriterLevel(plain, gzip.BestCompression)
	if err != nil {
		return []byte{}, fmt.Errorf("Invalid compression level: %v", err)
	}

	messageReader := bytes.NewReader(message)
	_, err = io.Copy(compressed, messageReader)
	if err != nil {
		return []byte{}, fmt.Errorf("Error writing encrypted file: %v", err)
	}

	compressed.Close()
	plain.Close()
	w.Close()

	return buf.Bytes(), nil
}
