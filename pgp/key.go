package pgp

import (
	"golang.org/x/crypto/openpgp/packet"
	"bytes"
	"errors"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp"
)

func getPublicKeyPacket(publicKey []byte) (*packet.PublicKey, error) {
	publicKeyReader := bytes.NewReader(publicKey)
	block, err := armor.Decode(publicKeyReader)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PublicKeyType {
		return nil, errors.New("Invalid public key data")
	}

	packetReader := packet.NewReader(block.Body)
	pkt, err := packetReader.Next()
	if err != nil {
		return nil, err
	}

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, err
	}
	return key, nil
}

func getPrivateKeyPacket(privateKey []byte) (*packet.PrivateKey, error) {
	privateKeyReader := bytes.NewReader(privateKey)
	block, err := armor.Decode(privateKeyReader)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PrivateKeyType {
		return nil, errors.New("Invalid private key data")
	}

	packetReader := packet.NewReader(block.Body)
	pkt, err := packetReader.Next()
	if err != nil {
		return nil, err
	}
	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		return nil, errors.New("Unable to cast to Private Key")
	}
	return key, nil
}
