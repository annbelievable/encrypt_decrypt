package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
)

func main() {
	fmt.Println("This is the secret.")
	key := []byte("xyzsomething_SwE3T-aNd/ADIctv!26")
	text := "Is this the real world?"

	cipheredText, err := encrypt([]byte(text), key)
	if err != nil {
		log.Fatalln(err.Error())
	}
	fmt.Println("encryption success: ", cipheredText)

	decryptedText, err := decrypt(cipheredText, key)
	if err != nil {
		log.Fatalln(err.Error())
	}
	fmt.Println("decryption success: ", string(decryptedText))
}

func encrypt(text, key []byte) ([]byte, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, text, nil), nil
}

//check hex.DecodeString
func decrypt(cipheredText []byte, key []byte) ([]byte, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(cipheredText) < nonceSize {
		return nil, err
	}

	nonce, encryptedMessage := cipheredText[:nonceSize], cipheredText[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedMessage, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
