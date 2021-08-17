package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

const (
	aesKeyFileExt = ".aes_key" //used to save aes key
	aesEncFileExt = ".aes_enc" //used to save aes encrypted text
)

func main() {
	label := "test"
	text := "Is this the real world?"

	EncryptText(label, text)
	decryptedText, err := DecryptText(label)
	if err != nil {
		log.Fatalf("Failed to decryp text: %s", err)
	}
	fmt.Printf("Decrypted text: %s", decryptedText)
}

func EncryptText(label, text string) {
	key, err := CreateKey()
	if err != nil {
		log.Fatalf("Failed to generate a key: %s", err)
	}

	cipheredText, err := Encrypt([]byte(text), key)
	if err != nil {
		log.Fatalf("Failed to encrypt text: %s", err)
	}

	err = SaveCipheredTextAndKey(label, cipheredText, key)
	if err != nil {
		log.Fatalf("Failed to save the ciphered text and key into file: %s", err)
	}

	fmt.Println("encryption success: ", cipheredText)
}

func SaveCipheredTextAndKey(label string, cipheredText, key []byte) error {
	enc_filename := label + aesEncFileExt
	key_filename := label + aesKeyFileExt

	err := SaveChipheredText(enc_filename, cipheredText)
	if err != nil {
		return err
	}

	err = SaveKey(key_filename, key)
	if err != nil {
		//if it fails here, delete the ciphered text file
		return err
	}

	return nil
}

func DecryptText(label string) ([]byte, error) {
	enc_filename := label + aesEncFileExt
	key_filename := label + aesKeyFileExt

	key, err := ReadKey(key_filename)
	if err != nil {
		log.Fatalf("Failed to read key from file: %s", err)
		return nil, err
	}
	cipheredText, err := ioutil.ReadFile(enc_filename)
	if err != nil {
		log.Fatalf("Failed to read ciphered text from file: %s", err)
		return nil, err
	}

	decryptedText, err := Decrypt(cipheredText, key)
	if err != nil {
		log.Fatalf("Failed to decrypt text: %s", err)
		return nil, err
	}
	return decryptedText, nil
}

func CreateKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func SaveKey(filename string, key []byte) error {
	block := &pem.Block{
		Type:  "AES KEY",
		Bytes: key,
	}
	err := ioutil.WriteFile(filename, pem.EncodeToMemory(block), 0644)
	if err != nil {
		return err
	}
	return nil
}

func ReadKey(filename string) ([]byte, error) {
	key, err := ioutil.ReadFile(filename)
	if err != nil {
		return key, err
	}
	block, _ := pem.Decode(key)
	return block.Bytes, nil
}

func SaveChipheredText(filename string, cipheredText []byte) error {
	err := ioutil.WriteFile(filename, cipheredText, 0644)
	if err != nil {
		return err
	}
	return nil
}

func Encrypt(text, key []byte) ([]byte, error) {
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

func Decrypt(cipheredText []byte, key []byte) ([]byte, error) {
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
