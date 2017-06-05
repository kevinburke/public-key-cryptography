package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

func generateKey() {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("public key: %s\n", base64.URLEncoding.EncodeToString(publicKey[:]))
	fmt.Printf("private key: %s\n", base64.URLEncoding.EncodeToString(privateKey[:]))
}

func newNonce() *[24]byte {
	nonce := new([24]byte)
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	return nonce
}

var publicKeyStr = "LF-s5obfbHD-u37zxIXAi_L4w9jW8zIGv9wq2qA2RyY="
var privateKeyStr = "IA-M_HvLXAFkfrnfDDlunkqKWRZTL6xMrFAONGEH2QY="

var peerPublicKeyStr = "4iTGQ_ryUjW8GG-SpF4g_ZFGRmx8hmc4UedewLCrDAs="
var peerPrivateKeyStr = "gWHZE3Asozs8virRpdqrzY68WkRz1mlJrIm9k0-iR_M="

func getKey(b64 string) (*[32]byte, error) {
	data, err := base64.URLEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("key has wrong length: %d, want 32", len(data))
	}
	key := new([32]byte)
	copy(key[:], data)
	return key, nil
}

func encrypt(msg []byte) []byte {
	nonce := newNonce()
	peerPublicKey, err := getKey(peerPublicKeyStr)
	if err != nil {
		panic(err)
	}
	privateKey, err := getKey(privateKeyStr)
	if err != nil {
		panic(err)
	}
	return box.Seal(nonce[:], msg, nonce, peerPublicKey, privateKey)
}

func decrypt(msg []byte) ([]byte, error) {
	if len(msg) <= 24 {
		return nil, errors.New("message is too short to decrypt")
	}
	nonce := new([24]byte)
	copy(nonce[:], msg[:24])
	publicKey, err := getKey(publicKeyStr)
	if err != nil {
		panic(err)
	}
	peerPrivateKey, err := getKey(peerPrivateKeyStr)
	if err != nil {
		panic(err)
	}
	out, ok := box.Open([]byte{}, msg[24:], nonce, publicKey, peerPrivateKey)
	if !ok {
		return nil, errors.New("Could not decrypt message")
	}
	return out, nil
}

var encryptedString = "dlsKgrbN832H1i5XqlB_HX7jYmR7QHc-IvbD-6HFMJdLH3c-ZLzkOqIu9ZqHNwyiFhm496AlRb1OAeCVYCFXhRH95DVCkjvFEk2NnoDNqft9uIYC0QfmpfctDsPxhoahti6hthkiW-B_z5R4mAZAupkkLZwM5hv4NOfgDPNzM_swm-8="

func main() {
	//data, err := base64.URLEncoding.DecodeString(encryptedString)
	//if err != nil {
	//log.Fatal(err)
	//}
	//msg, err := decrypt(data)
	//if err != nil {
	//log.Fatal(err)
	//}
	//fmt.Println("msg", string(msg))

	generateKey()
}
