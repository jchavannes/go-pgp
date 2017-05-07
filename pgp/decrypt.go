package pgp

import (
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	_ "crypto/sha256"
	_ "golang.org/x/crypto/ripemd160"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"compress/gzip"
)

func Decrypt(entity *openpgp.Entity, encrypted []byte) ([]byte, error) {
	block, err := armor.Decode(bytes.NewReader(encrypted))
	if err != nil {
		return []byte{}, fmt.Errorf("Error decoding: %v", err)
	}

	if block.Type != "Message" {
		return []byte{}, errors.New("Invalid message type")
	}

	var entityList openpgp.EntityList
	entityList = append(entityList, entity)

	messageReader, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading message: %v", err)
	}

	read, err := ioutil.ReadAll(messageReader.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading unverified body: %v", err)
	}
	fmt.Printf("Read: %s\n", read)

	reader := bytes.NewReader(read)

	uncompressed, err := gzip.NewReader(reader)
	if err != nil {
		return []byte{}, fmt.Errorf("Error initializing gzip reader: %v", err)
	}
	defer uncompressed.Close()

	return ioutil.ReadAll(uncompressed)
}
