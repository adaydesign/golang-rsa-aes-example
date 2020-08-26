package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"rsa2/crypto"
	"rsa2/internal/pki"
)

func main() {

	// ------------------------------- Test RSA -----------------------------------
	// demoRSAGenKEYPair()
	// demoRSA()

	// ------------------------------- Test AES -----------------------------------
	// demoAES()

	// ----------------------Text Full use RSA E(AES-KEY) -------------------------
	demoFull()
}

func demoFull() {
	bodyEncodeKey := `aes-key-for-deco` // <<- auto generate (16 bit)
	fmt.Println("-- 1. (SENDER) Define [AES KEY] (body encode key)")
	fmt.Println(bodyEncodeKey)
	fmt.Println()
	// encode body data by AES
	bodyData := `{
		"glossary": {
			"title": "example glossary",
			"GlossDiv": {
				"title": "S",
				"GlossList": {
					"GlossEntry": {
						"ID": "SGML",
						"SortAs": "SGML",
						"GlossTerm": "Standard Generalized Markup Language",
						"Acronym": "SGML",
						"Abbrev": "ISO 8879:1986",
						"GlossDef": {
							"para": "A meta-markup language, used to create markup languages such as DocBook.",
							"GlossSeeAlso": ["GML", "XML"]
						},
						"GlossSee": "markup"
					}
				}
			}
		}
	}`

	fmt.Println("-- 2. (SENDER) Encode body message by [AES KEY] --")
	aesKey := demoAESMakeKey(bodyEncodeKey)
	bodyCipher, nonce := demoAESEncrypt(aesKey, bodyData)
	fmt.Println()

	// Encrypt BODY-Encode-KEY by RSA
	// Decrypt
	fmt.Println("-- 3. (SENDER) Encode [AES KEY] by RSA --")

	encryptedKey, err := pki.Encrypt("./keys/public.key", bodyEncodeKey)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(encryptedKey)

	fmt.Println()
	fmt.Println("-- 4. (SENDER) send encrypted KEY and Message and nonce thought Network to (RECIEVER)")
	fmt.Println("..... >>>>")
	fmt.Println("..... >>>>")
	fmt.Println()

	fmt.Println("-- 5. (RECIEVER) Decode encrypted KEY --")
	decryptedKey, err := pki.Decrypt("./keys/private.key", encryptedKey)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(decryptedKey)
	fmt.Println()

	// Decrypt apiKeyCipher by AES
	fmt.Println("-- 6.(RECIEVER) Decode Body Message by (AES-KEY) --")
	dKey := demoAESMakeKey(decryptedKey)
	demoAESDecrypt(dKey, bodyCipher, nonce)

}

func demoRSA() {
	// Test Online : https://8gwifi.org/RSAFunctionality?keysize=2048

	/*
		So basicly you divide the key length with 8 -11(if you have padding).
		For example if you have a 2048bit key you can encrypt 2048/8 = 256 bytes (- 11 bytes if you have padding).
		Q&A : https://stackoverflow.com/questions/10007147/getting-a-illegalblocksizeexception-data-must-not-be-longer-than-256-bytes-when
	*/

	/* // test JSON Data
	body := `{"widget": {
		"debug": "on",
		"window": {
		"title": "Sample Konfabulator Widget",
		"name": "main_window"
		}
	   }}`
	*/

	// test API KEY Data
	body := "x/jG7n89tjKb/f3I0cLwG4wPFcZ5Zql67dsPFaqse97LDqXEpz4dgU9PCXoowVtld2cujdGeP98+OY8WEUH0+U9XoyU28zvSoca2EGvCprY/Dis="

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

func demoRSAEncryptionDecryption(plainText string, pkPath string, pbPath string) (decryptText string) {
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

	return decryptedMessage
}

func demoAES() {
	key := demoAESMakeKey("@PITSD2020-08030-2132321")
	cipher, nonce := demoAESEncrypt(key, `{"username":"tsd","createdAt":"2020-08-30","expireAt":"2021-08-30"}`)

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
	// check key Length : https://www.devglan.com/online-tools/aes-encryption-decryption

	// AES 128 bit use key length 16 bit
	// AES 196 bit use key length 24 bit
	// AES 256 bit use key length 32 bit
	keyText := []byte(char16) // 16 character
	keyDst := make([]byte, hex.EncodedLen(16))
	hex.Encode(keyDst, keyText)

	return keyDst
}

func demoAESEncrypt(keyByte []byte, plainText string) (cipher string, nonce string) {
	key := hex.EncodeToString(keyByte)
	fmt.Println("KEY Encrypt")
	fmt.Println(key)
	// plainText := "{username:'tsd',createdAt:'2020-08-30',expireAt:'2021-08-30'}"
	cipherByte, nonceByte, err := crypto.ExampleNewGCM_encrypt(key, plainText)

	if err != nil {
		panic(err.Error())
	}

	cipherBase64 := base64.StdEncoding.EncodeToString(cipherByte)
	// cipherString := hex.EncodeToString(cipherByte)
	nonceString := hex.EncodeToString(nonceByte)
	fmt.Println("Ciphertext")
	//fmt.Println(cipherString)
	fmt.Println(cipherBase64)
	fmt.Println("nonce")
	fmt.Println(nonceString)

	return cipherBase64, nonceString
}

func demoAESDecrypt(keyByte []byte, cipherString string, nonceString string) {
	key := hex.EncodeToString(keyByte)
	decrypText, err := crypto.ExampleNewGCM_decrypt(key, cipherString, nonceString)

	if err != nil {
		panic(err.Error())
	}

	decrypString := hex.EncodeToString(decrypText)
	dd, err := hex.DecodeString(decrypString)

	fmt.Println("Decode Message")
	if err != nil {
		panic(err.Error())
	} else {
		fmt.Println(string(dd))
	}
}

func demoAESCFBEncrypt(keyByte []byte, plainText string) (cipher string) {
	key := hex.EncodeToString(keyByte)
	fmt.Println("KEY Encrypt")
	fmt.Println(key)
	// plainText := "{username:'tsd',createdAt:'2020-08-30',expireAt:'2021-08-30'}"
	cipherByte, err := crypto.ExampleNewCFBEncrypter(key, plainText)

	if err != nil {
		panic(err.Error())
	}

	cipherBase64 := base64.StdEncoding.EncodeToString(cipherByte)
	// cipherString := hex.EncodeToString(cipherByte)
	fmt.Println("Ciphertext")
	//fmt.Println(cipherString)
	fmt.Println(cipherBase64)

	return cipherBase64
}

func demoAESCFBDecrypt(keyByte []byte, cipherString string) {
	key := hex.EncodeToString(keyByte)
	decrypText, err := crypto.ExampleNewCFBDecrypter(key, cipherString)

	if err != nil {
		panic(err.Error())
	}

	decrypString := hex.EncodeToString(decrypText)
	dd, err := hex.DecodeString(decrypString)

	fmt.Println("Decode Message")
	if err != nil {
		panic(err.Error())
	} else {
		fmt.Println(string(dd))
	}
}
