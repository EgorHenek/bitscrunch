package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
)

const (
	host = "https://api-testnet.bitscrunch.com"
	path = "/api/v1/market/metrics?currency=usd&blockchain=1&metrics=holders&metrics=marketcap&time_range=24h&include_washtrade=true"
)

type AccessKey struct {
	Key       string
	PublicKey string
	Name      string
}

func main() {
	keyPath := flag.String("key-path", "./access-key.json", "path to access key")
	repatedCount := flag.Int("count", 10, "number of requests")

	flag.Parse()

	keyData, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("failed to read key file: %v", err)
	}

	var accessKey AccessKey

	if err := json.Unmarshal(keyData, &accessKey); err != nil {
		log.Fatalf("failed to unmarshal key data: %v", err)
	}

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, host+path, nil)
	if err != nil {
		log.Fatalf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("name", accessKey.Name)
	req.Header.Set("pubkey", accessKey.PublicKey)

	for i := 0; i < *repatedCount; i++ {
		rid, err := uuid.NewUUID()
		if err != nil {
			log.Fatalf("failed to generate uuid: %v", err)
		}

		message := fmt.Sprintf("%s:GET:%s::", rid.String(), path)
		sign, err := signMessage(&accessKey, message)
		if err != nil {
			log.Fatalf("failed to sign message: %v", err)
		}

		req.Header.Set("rId", rid.String())
		req.Header.Set("Sign", sign)
		req.Header.Set("meesage", message)

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("failed to send request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("failed to read response body: %v", err)
		}

		fmt.Println(string(body))
	}
}

func (key *AccessKey) getPrivateKey() (*ecdsa.PrivateKey, error) {
	pemKey := fmt.Sprintf(`-----BEGIN RSA PRIVATE KEY-----
%s
-----END RSA PRIVATE KEY-----`, key.Key)
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey.(*ecdsa.PrivateKey), nil
}

func signMessage(key *AccessKey, message string) (string, error) {
	privateKey, err := key.getPrivateKey()
	if err != nil {
		return "", err
	}

	hashed := sha256.Sum256([]byte(message))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}
