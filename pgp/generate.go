package pgp

import (
	"golang.org/x/crypto/openpgp"
	"bytes"
	"golang.org/x/crypto/openpgp/armor"
)

type PGPKeyPair struct {
	PublicKey  string
	PrivateKey string
}

func GenerateKeyPair(fullname string, comment string, email string) (PGPKeyPair, error) {
	var e *openpgp.Entity
	e, err := openpgp.NewEntity(fullname, comment, email, nil)
	if err != nil {
		return PGPKeyPair{}, err
	}

	for _, id := range e.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
		if err != nil {
			return PGPKeyPair{}, err
		}
	}

	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return PGPKeyPair{}, err
	}
	e.Serialize(w)
	w.Close()
	pubKey := buf.String()

	buf = new(bytes.Buffer)
	w, err = armor.Encode(buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return PGPKeyPair{}, err
	}
	e.SerializePrivate(w, nil)
	w.Close()
	privateKey := buf.String()

	return PGPKeyPair{
		PublicKey: pubKey,
		PrivateKey: privateKey,
	}, nil
}
