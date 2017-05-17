package pgp_test

import (
	"errors"
	"fmt"
	"github.com/jchavannes/go-pgp/pgp"
	"testing"
)

func TestEncrypt(t *testing.T) {
	fmt.Println("Entcrypt test: START")
	pubEntity, err := pgp.GetEntity([]byte(TestPublicKey), []byte{})
	if err != nil {
		t.Error(fmt.Errorf("Error getting entity: %v", err))
	}
	fmt.Println("Created public key entity.")

	encrypted, err := pgp.Encrypt(pubEntity, []byte(TestMessage))
	if err != nil {
		t.Error(err)
	}
	fmt.Println("Encrypted test message with public key entity.")

	privEntity, err := pgp.GetEntity([]byte(TestPublicKey), []byte(TestPrivateKey))
	if err != nil {
		t.Error(fmt.Errorf("Error getting entity: %v", err))
	}
	fmt.Println("Created private key entity.")

	decrypted, err := pgp.Decrypt(privEntity, encrypted)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("Decrypted message with private key entity.")

	decryptedMessage := string(decrypted)
	if decryptedMessage != TestMessage {
		t.Error(errors.New("Decrypted message does not equal original."))
	}
	fmt.Println("Decrypted message equals original message.")
	fmt.Println("Entcrypt test: END\n")
}

const TestMessage = "hello world"

const TestPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xcZYBFkNK+ABEADUpjJ/kz3j+iz9qnzUb6ONw+WHSLp8umnd1z06SBVkWFjYReqf
oPCOq67XDseK71ZSevrIt7EdTLAzl0xN8kB+8iedAGM5OCakDe3R8L83OGy1Em26
PbrrYs3TYKGDXW65TsGYCoETROGgU2zPvuBDU1RvVvd9vAlWHQis43BOWaaakCEc
00V3sdNcfV+lz7fNUXEgtmTCCr9NWX4gO3YeenIIxep4WD27VwscW5Q2B1cnxcFL
+TZzE2oVjtXljGSO94XsekuNU47zwJZNGyU6SSlSZ+KVXuSdkRRfNYHlgDWg5b8C
xVmdVUfsx3bmNlOlXoyETj83xvRlLxn3PYIgOz6OlYGba5oDogK2QLXGTXK1o9OE
kgoghmCNQqxocvb1hQXT8cEynIbAdc6/JknYaoic6ka1iTTz3uN8FEPw5gRlidcQ
3wkbmqIS0LJs3JmVbD7/BxMY1dwqMyvulfnLiTsWSPvk41o7dHf077t23V9w78Jg
h4Xq4HRvt37PtuO6eWW3c5aUIWmvvDqMbMEqp2y23noYoVNqEpVoHolDdoCSurv/
XxbNBnj46XwaIs6OlrO2htV0al2/WVTNnSLxCyoHXoJEDXyaOyNKn1jM/FczgYQJ
069uC804ohOfjLmbtUEYE7Hjeo5utPm2ryjnakgV5AStKgL0SyFZUwN/DwARAQAB
AA//TUk2M03FgbUsYulywxbsH5siMeAJ/0kVLw6Kb0NBmx3M9JW8p1Wr+H6HZhw2
A9XmzsVpnke89IQpyiZkEjRIoprKMPKyHVq+GIQDenkAVkaIo+rVvImxBNn9KqUF
LqRnmKv6CpNOxD0Vr9qCQqMCCRYhKvI1sxoDXqvguk1TRPaqaaSWlE5pAg68XfIn
MDFlgRbngdcomamkS62J/Jb/4CXqiiu8gw63KP6CyES0gkp6r7bdAQrLclmNBdbL
AMncxmVJ5F+yU+QZoZfOSKnkBuIORagCHv3FI0tWVyAwXMQTOa4mlRA6+MbFBFae
bR8zmXfapD94FIKX0qqiykwtnXWom1Sl4S865c06qwEZzxpCUSeVDxE4JzzOixFI
RjscMQ+zsjdMUNBCwaslxLYs9nLHXiWbC2HMdnEnStLqF8SL5RSW23Ud/f9G+QnJ
urh/LWerWy7usVMERdBBglVcubTX3AzY5/pQJByCOlURnMzgvsUJYJzcEO4wVzNG
VVojB5ku+c/H5cG+ENNGm6F0PUjpJfysQElgPHwcBGAtwJmhF6treLwtFPzU/OwM
FGNLzsnTcytTjGppYfmy6hgvkmovTrXhZFovaAPC3VQJCbhkjVOAHebMmEPTqEm+
s5aVhcBnmhKsGoSrKQyFUFpG5ECgEF9ibzT0YqeYvWkcRREIAO4FvsEUi4pBzJQU
TFl+0x8PXw/Z4xTESdNl2LZSghb3ZJKmT3oXIUDTcLir6Ic+WLBmfmnr9GtS6D22
ugUywY1lDJ0tw4dPBhxIvkQjOw9pYu/NEL3KVNFFLT5GhOqjThpKkFnWkaPnSrku
I2FJ9y0wEO+m6hfIUrm/zbE5hn74amaq12+y4CTxYPOeeAnpmyoRjCOIkP5DK8Tn
xE1op04McL72tWtnHglbWDxDuL4BGZPvewvrOQNViv64tGIjifQguVKhbvJfEefY
ZZfNqR/jZ7ewIoIHzDyuH34piVabF6Ok3spc1dYeOSVZaAmUfO7L5knzaJgSjeTL
lO9+UMkIAOS12dgLtgGxwQWFg253S1rTSvM4GbBat3H3/MkauB5YRqufm2Rz0qZZ
FcnCjRCAWiqkdSOZf+w4LNKbQXBKu06Q8w1mSiEfphGrFbWuwVA8gSD8B6XVjt+h
+V84SvmlJt12iaUw8gLG3WDzOdPfzdcjwrA3xqIpX/AX8AvdTklLTbTU6rY4A19t
F35hmi8Pl1g6lLcoYDqkygUlso+IXDG4szOBv58rC01FwyTq5/vDUjEu8k/iVdIf
4KkZ/+Wh0Nml+b0/LyemWVAiT27YwIProBvswj1/XBLEuukinb9z0SQ4tJpV/z4q
nCmHmXzSXvHK6byfmrV5tNN5Ug5b1RcH/i/I1ppuMlBzOJ/QBq144DYs5EaWC45c
kuZq+C9Rsw1gbm3f/RROdH6Old9w/ObsMJX2UBlWL0gVz4G7ONCO+d1azg4HLc2x
XoK9GR8SFCSHIRwVortddFLJBS7Sw1CI9wJCj6JulH3YIS2S4T5JE+VLf+2wdg7b
Cmj5ePpXcoCvLi1apbbR0KMy5ngjkVlhNHtcJjShP+Twzga7TMocAyNX4TGF4ZQS
1prsZxBcuexrPxns0GIKki4pvEy3+LGRru5U8okdeaIvL/Wh/JpoCwA6oqZiNqTI
gTr5xa2OOzDFAQx5I0tShJ+N+8Cte+OWI5zav8YEDMmyrE/iBG9oHKlvqA==
=5NT7
-----END PGP PRIVATE KEY BLOCK-----`

const TestPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBFkNK+ABEADUpjJ/kz3j+iz9qnzUb6ONw+WHSLp8umnd1z06SBVkWFjYReqf
oPCOq67XDseK71ZSevrIt7EdTLAzl0xN8kB+8iedAGM5OCakDe3R8L83OGy1Em26
PbrrYs3TYKGDXW65TsGYCoETROGgU2zPvuBDU1RvVvd9vAlWHQis43BOWaaakCEc
00V3sdNcfV+lz7fNUXEgtmTCCr9NWX4gO3YeenIIxep4WD27VwscW5Q2B1cnxcFL
+TZzE2oVjtXljGSO94XsekuNU47zwJZNGyU6SSlSZ+KVXuSdkRRfNYHlgDWg5b8C
xVmdVUfsx3bmNlOlXoyETj83xvRlLxn3PYIgOz6OlYGba5oDogK2QLXGTXK1o9OE
kgoghmCNQqxocvb1hQXT8cEynIbAdc6/JknYaoic6ka1iTTz3uN8FEPw5gRlidcQ
3wkbmqIS0LJs3JmVbD7/BxMY1dwqMyvulfnLiTsWSPvk41o7dHf077t23V9w78Jg
h4Xq4HRvt37PtuO6eWW3c5aUIWmvvDqMbMEqp2y23noYoVNqEpVoHolDdoCSurv/
XxbNBnj46XwaIs6OlrO2htV0al2/WVTNnSLxCyoHXoJEDXyaOyNKn1jM/FczgYQJ
069uC804ohOfjLmbtUEYE7Hjeo5utPm2ryjnakgV5AStKgL0SyFZUwN/DwARAQAB
=gO1a
-----END PGP PUBLIC KEY BLOCK-----`

