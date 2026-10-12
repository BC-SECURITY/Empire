package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// deriveSubkeys splits a shared key into independent (cipher, MAC) subkeys.
// Must stay byte-for-byte identical to the server's
// HKDF(SHA256, length=32, salt=None, info=label).
func deriveSubkeys(key []byte) ([]byte, []byte) {
	kEnc := make([]byte, 32)
	kMac := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, key, nil, []byte("empire-enc")), kEnc)
	io.ReadFull(hkdf.New(sha256.New, key, nil, []byte("empire-mac")), kMac)
	return kEnc, kMac
}

func AesEncryptThenHMAC(key, data []byte) []byte {
	kEnc, kMac := deriveSubkeys(key)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(kEnc)
	if err != nil {
		panic(err)
	}

	padSize := aes.BlockSize - len(data)%aes.BlockSize
	padding := bytes.Repeat([]byte{byte(padSize)}, padSize)
	data = append(data, padding...)

	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)

	ciphertext = append(iv, ciphertext...)

	h := hmac.New(sha256.New, kMac)
	h.Write(ciphertext)
	hmacValue := h.Sum(nil)[:16]

	finalData := append(ciphertext, hmacValue...)
	return finalData
}

func verifyHMAC(key, data []byte) bool {
	if len(data) <= 16 {
		return false
	}

	_, kMac := deriveSubkeys(key)
	mac := data[len(data)-16:]
	data = data[:len(data)-16]

	expectedMAC := hmac.New(sha256.New, kMac)
	expectedMAC.Write(data)
	expectedMACDigest := expectedMAC.Sum(nil)[:16]

	// fmt.Printf("Data: %x\n", data)
	// fmt.Printf("MAC: %x\n", mac)
	// fmt.Printf("Expected MAC: %x\n", expectedMACDigest)

	return hmac.Equal(mac, expectedMACDigest)
}

func AesDecryptAndVerify(key, data []byte) ([]byte, error) {
	if !verifyHMAC(key, data) {
		return nil, fmt.Errorf("invalid ciphertext received")
	}

	kEnc, _ := deriveSubkeys(key)
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize : len(data)-16]

	block, err := aes.NewCipher(kEnc)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	padding := int(ciphertext[len(ciphertext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	for _, padByte := range ciphertext[len(ciphertext)-padding:] {
		if int(padByte) != padding {
			return nil, fmt.Errorf("invalid padding byte")
		}
	}

	return ciphertext[:len(ciphertext)-padding], nil
}
