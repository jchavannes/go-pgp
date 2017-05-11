# Go PGP

Layer on top of `golang.org/x/crypto/openpgp` to handle a few PGP use cases.

## Examples

### Encryption

[pgp/encrypt_test.go](pgp/encrypt_test.go)

#### Encrypt

```go
// Create public key entity
publicKeyPacket, _ := pgp.GetPublicKeyPacket([]byte(TestPublicKey))
pubEntity, _ := pgp.CreateEntityFromKeys(publicKeyPacket, nil)

// Encrypt message
encrypted, _ := pgp.Encrypt(pubEntity, []byte(TestMessage))
```

#### Decrypt

```go
// Create private key entity
privEntity, _ := pgp.GetEntity([]byte(TestPublicKey), []byte(TestPrivateKey))

// Decrypt message
decrypted, _ := pgp.Decrypt(privEntity, encrypted)
```

### Signing

[pgp/sign_test.go](pgp/sign_test.go)

#### Sign

```go
// Create private key entity
entity, _ := pgp.GetEntity([]byte(TestPublicKey), []byte(TestPrivateKey))

// Sign message
signature, _ := pgp.Sign(entity, []byte(TestMessage))
```

#### Verify

```go
// Create public key packet
pubKeyPacket, _ := pgp.GetPublicKeyPacket([]byte(TestPublicKey))

// Verify signature
err = pgp.Verify(pubKeyPacket, []byte(TestMessage), signature)
if err == nil {
    fmt.Println("Signature verified.")
}
```
