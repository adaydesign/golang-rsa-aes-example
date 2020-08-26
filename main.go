package main

import (
	"encoding/hex"
	"fmt"
	"rsa2/crypto"
)

func main() {

	// ------------------------------- Test RSA -----------------------------------

	// // Step 1. Generate Key
	// key, err := pki.New()
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// fmt.Println(key.PublicKeyToPemString())
	// fmt.Println(key.PrivateKeyToPemString())

	// // Step 2.1 Test Encrypt text
	// plainText := "This is a very secret message :)"

	// encryptedMessage, err := pki.Encrypt("./keys/public.key", plainText)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// fmt.Println(encryptedMessage)

	// // Step 2.2 Test Decrypt cipher text
	// decryptedMessage, err := pki.Decrypt("./keys/private.key", encryptedMessage)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// fmt.Println(decryptedMessage)

	// ------------------------------------------------------------------------------

	// ------------------------------- Test AES -----------------------------------

	key := "6368616e676520746869732070617373776f726420746f206120736563726574"
	plainText := "{username:'tsd',createdAt:'2020-08-30',expireAt:'2021-08-30'}"
	cipher, nonce := crypto.ExampleNewGCM_encrypt(key, plainText)

	cipherString := hex.EncodeToString(cipher)
	fmt.Println("API KEY for TSD")
	fmt.Println(cipherString)

	nonceString := hex.EncodeToString(nonce)
	decrypText := crypto.ExampleNewGCM_decrypt(key, cipherString, nonceString)

	decrypString := hex.EncodeToString(decrypText)
	dd, err := hex.DecodeString(decrypString)

	fmt.Println("Decode API KEY")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(string(dd))
	}

}
