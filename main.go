package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"rsa2/crypto"
	"rsa2/internal/pki"
)

func main() {

	// ------------------------------- Test RSA -----------------------------------
	demoRSAGenKEYPair()
	demoRSA()

	// ------------------------------- Test AES -----------------------------------
	demoAES()

}

func demoRSA() {
	// Test Online : https://8gwifi.org/RSAFunctionality?keysize=2048

	/*
		So basicly you divide the key length with 8 -11(if you have padding). For example if you have a 2048bit key you can encrypt 2048/8 = 256 bytes (- 11 bytes if you have padding).
		Q&A : https://stackoverflow.com/questions/10007147/getting-a-illegalblocksizeexception-data-must-not-be-longer-than-256-bytes-when
	*/
	body := `{"widget": {
		"debug": "on",
		"window": {
		"title": "Sample Konfabulator Widget",
		"name": "main_window"
		}
	   }}`

	demoRSAEncryptionDecryption(body, "./keys/private.key", "./keys/public.key")
}

func demoRSAGenKEYPair() {
	// Step 1. Generate Key
	key, err := pki.New()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(key.PublicKeyToPemString())
	fmt.Println(key.PrivateKeyToPemString())
}

func demoRSAEncryptionDecryption(plainText string, pkPath string, pbPath string) {
	// Step 2.1 Test Encrypt text
	encryptedMessage, err := pki.Encrypt(pbPath, plainText)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(encryptedMessage)

	// Step 2.2 Test Decrypt cipher text
	decryptedMessage, err := pki.Decrypt(pkPath, encryptedMessage)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(decryptedMessage)
}

func demoAES() {
	key := demoAESMakeKey("@PITSD2020-08030")
	cipher, nonce := demoAESEncrypt(key, "{username:'tsd',createdAt:'2020-08-30',expireAt:'2021-08-30'}")

	/*
		// Test API-KEY
		// Use KEY from generated
		key, _ := hex.DecodeString("3231346434303662363535343533343432643431353034393264346234353539")
		// from GCM Encryption - Message Authentication
		nonce := "1b18cde93ce97d68060bcfd3"
		// TSD-API-KEY
		cipher := "a4947bcb0039f9746321b7c64e96061eca34d0ddd2ebe08eb4fc737304ea5d8c150f712005857d774e7343453aa84a898747a3043e12e9aa2d165a716fcd0eb0bb107cc5912c5ac8100fd11b2d"
	*/

	demoAESDecrypt(key, cipher, nonce)
}

func demoAESMakeKey(char16 string) (key []byte) {
	keyText := []byte(char16) // 16 character
	keyDst := make([]byte, hex.EncodedLen(16))
	hex.Encode(keyDst, keyText)

	return keyDst
}

func demoAESEncrypt(keyByte []byte, plainText string) (cipher string, nonce string) {
	key := hex.EncodeToString(keyByte)
	fmt.Println("KEY Encrypt -- KEEP")
	fmt.Println(key)
	// plainText := "{username:'tsd',createdAt:'2020-08-30',expireAt:'2021-08-30'}"
	cipherByte, nonceByte, err := crypto.ExampleNewGCM_encrypt(key, plainText)

	if err != nil {
		panic(err.Error())
	}

	cipherString := hex.EncodeToString(cipherByte)
	nonceString := hex.EncodeToString(nonceByte)
	fmt.Println("API KEY for TSD (ciphertext)")
	fmt.Println(cipherString)
	fmt.Println("nonce -- KEEP")
	fmt.Println(nonceString)

	return cipherString, nonceString
}

func demoAESDecrypt(keyByte []byte, cipherString string, nonceString string) {
	key := hex.EncodeToString(keyByte)
	decrypText, err := crypto.ExampleNewGCM_decrypt(key, cipherString, nonceString)

	if err != nil {
		panic(err.Error())
	}

	decrypString := hex.EncodeToString(decrypText)
	dd, err := hex.DecodeString(decrypString)

	fmt.Println("Decode API KEY")
	if err != nil {
		panic(err.Error())
	} else {
		fmt.Println(string(dd))
	}
}
