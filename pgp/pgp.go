package pgp

import (
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"bytes"
	"golang.org/x/crypto/openpgp/packet"
	_ "crypto/sha256"
	_ "golang.org/x/crypto/ripemd160"
	"crypto"
	"errors"
	"fmt"
	"io"
	"compress/gzip"
	"io/ioutil"
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

func GetEntity(publicKey []byte, privateKey []byte) (*openpgp.Entity, error) {
	publicKeyEntity, err := GetPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	privateKeyEntity, err := GetPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return createEntityFromKeys(publicKeyEntity, privateKeyEntity)
}

func GetPublicKey(publicKey []byte) (*packet.PublicKey, error) {
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

func GetPrivateKey(privateKey []byte) (*packet.PrivateKey, error) {
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

// From https://gist.github.com/eliquious/9e96017f47d9bd43cdf9
func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) (*openpgp.Entity, error) {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: 4096,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey: pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e, nil
}
