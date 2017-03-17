package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

var hostnameFlag = flag.String("hostname", "attest.android.com", "Hostname for certificate validation")

func loadCertificate(b64data string) (*x509.Certificate, error) {
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(b64data)))
	l, err := base64.StdEncoding.Decode(buf, []byte(b64data))
	if err != nil {
		return nil, fmt.Errorf("Invalid base64 encoding")
	}
	cert, err := x509.ParseCertificate(buf[:l])
	if err != nil {
		return nil, fmt.Errorf("Cannot parse certificate: %v", err)
	}
	return cert, nil
}

func ValidateToken(tokenStr string) (*jwt.Token, error) {
	parser := new(jwt.Parser)
	parser.UseJSONNumber = true
	parser.ValidMethods = []string{"RS256", "RS384", "RS512"}
	parsed, err := parser.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Extract certificates from x5c header
		certStrings, ok := token.Header["x5c"].([]interface{})
		if !ok {
			return nil, fmt.Errorf("Missing certificates (x5c) in header")
		}
		certs := make([]*x509.Certificate, len(certStrings))
		for i, v := range certStrings {
			certString, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("Invalid type in certificate list")
			}
			cert, err := loadCertificate(certString)
			if err != nil {
				return nil, fmt.Errorf("Malformed certificate at index %d: %v", i, err)
			}
			certs[i] = cert
		}
		if len(certs) < 1 {
			return nil, fmt.Errorf("Empty certificate list in header")
		}
		mainCert := certs[0]
		chainCerts := certs[1:]

		// Validate certificates
		intermediatePool := x509.NewCertPool()
		for _, cert := range chainCerts {
			intermediatePool.AddCert(cert)
		}
		verifyOpts := x509.VerifyOptions{
			DNSName:       *hostnameFlag,
			Intermediates: intermediatePool,
		}
		if _, err := mainCert.Verify(verifyOpts); err != nil {
			return nil, fmt.Errorf("Invalid signing certificate: %v", err)
		}

		return mainCert.PublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("Parse error: %v", err)
	}

	if !parsed.Valid {
		return nil, fmt.Errorf("Token is not valid")
	}

	if err := parsed.Claims.Valid(); err != nil {
		return nil, fmt.Errorf("Invalid claims: %v", err)
	}

	return parsed, err
}

func main() {
	flag.Parse()

	tokenBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Error reading input: %v", err)
	}

	token, err := ValidateToken(strings.TrimSpace(string(tokenBytes)))
	if err != nil {
		log.Fatalf("Failed to validate token: %v", err)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.Encode(token.Claims)
}
