package main

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	mrand "math/rand"
	"time"

	"github.com/amitkgupta/x509utils"
)

func main() {
	a, aKey := generate(true, "a", nil, nil)
	b, bKey := generate(true, "b", nil, nil)
	c, _ := generate(true, "c", nil, nil)
	a1, a1Key := generate(true, "a1", a, aKey)
	a2, a2Key := generate(true, "a2", a, aKey)
	a3, _ := generate(false, "a3", a, aKey)
	b1, b1Key := generate(true, "b1", b, bKey)
	b2, _ := generate(false, "b2", b, bKey)
	a1i, _ := generate(true, "a1i", a1, a1Key)
	a1ii, _ := generate(false, "a1ii", a1, a1Key)
	a2i, _ := generate(false, "a2i", a2, a2Key)
	a2ii, _ := generate(false, "a2ii", a2, a2Key)
	b1i, _ := generate(false, "b1i", b1, b1Key)
	b1ii, b1iiKey := generate(true, "b1ii", b1, b1Key)
	b1iiA, _ := generate(false, "b1iiA", b1ii, b1iiKey)

	list := []*x509.Certificate{b1iiA, a2i, b1, a, b1ii, a1ii, a3, b2, c, b, a2ii, a2, a1, a1i, b1i}
	for _, cert := range list {
		println(cert.Subject.CommonName)
	}

	println()

	x509utils.SortByDepth(list)
	for _, cert := range list {
		println(cert.Subject.CommonName)
	}
}

func generate(isCA bool, commonName string, issuer *x509.Certificate, issuerSigningKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:         isCA,
		Subject:      pkix.Name{CommonName: commonName},
		SerialNumber: big.NewInt(mrand.Int63()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	var parent *x509.Certificate
	if issuer == nil {
		parent = template
	} else {
		parent = issuer
	}

	var signingKey crypto.Signer
	if issuerSigningKey == nil {
		signingKey = key
	} else {
		signingKey = issuerSigningKey
	}

	certBytes, err := x509.CreateCertificate(crand.Reader, template, parent, key.Public(), signingKey)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic(err)
	}

	return cert, key
}
