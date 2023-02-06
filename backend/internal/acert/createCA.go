package acert

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

func CreateCA() (err error) {
	// структупа сертификата CA
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Arkadii, INC. (CA)"},
			Country:       []string{"RU"},
			Province:      []string{"Spb"},
			Locality:      []string{"Saint Petersburg"},
			StreetAddress: []string{"Podvale 15"},
			PostalCode:    []string{"194000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 лет
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		//SubjectKeyId://
	}
	// Генерация приватноко ключа
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	// Генерация сертификата
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}
	// Закодируем сертификат в PEM
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err := ioutil.WriteFile("/usr/certs/out/certTestCA.crt", caPEM.Bytes(), 0777); err != nil {
		return err
	}

	// закодируем приватный ключ в PEM
	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err := ioutil.WriteFile("/usr/certs/out/certTestCA.key", caPrivKeyPEM.Bytes(), 0777); err != nil {
		return err
	}
	// создаем ласт отзыва
	ca1, caPrivKey1, err := LoadX509KeyPair("/usr/certs/out/certTestCA.crt", "/usr/certs/out/certTestCA.key")
	if err != nil {
		log.Println("Не прочитатьCA", err)
		return err
	}
	revoc, err := CreateRevocationList(ca1, caPrivKey1)
	if err != nil {
		log.Println("Ошибка создания листа отзывов", err.Error())
		return err
	}
	// ---------
	recvPEM := new(bytes.Buffer)
	pem.Encode(recvPEM, &pem.Block{
		Type:  "X509 CRL",
		Bytes: revoc, // x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err := ioutil.WriteFile("/usr/certs/out/certTestRecv.crl", recvPEM.Bytes(), 0444); err != nil {
		return err
	}
	///------------

	// читаем лист отзыва  .. читается..
	if err := ioutil.WriteFile("/usr/certs/out/certTestCA.crl", revoc, 0777); err != nil {
		return err
	}

	rev, err1 := x509.ParseRevocationList(revoc)
	if err1 != nil {
		log.Println("Чтение отзывов", err1.Error())
	}

	err2 := rev.CheckSignatureFrom(ca1)
	if err2 != nil {
		log.Println("Проверка подписи списка отзыва", err.Error())
	}

	log.Println("лист отзыва:", rev.Issuer.Organization)
	return nil
}
func CreateRevocationList(ca *x509.Certificate, priv crypto.Signer) ([]byte, error) {
	revList := &x509.RevocationList{
		Number: big.NewInt(1),
		// Issuer: pkix.Name{
		// 	Organization:  []string{"Arkadii, INC. (revocate)"},
		// 	Country:       []string{"RU"},
		// 	Province:      []string{"Spb"},
		// 	Locality:      []string{"Saint Petersburg"},
		// 	StreetAddress: []string{"Podvale 15"},
		// 	PostalCode:    []string{"194000"},
		// },
	}
	revoc, err := x509.CreateRevocationList(rand.Reader, revList, ca, priv)
	return revoc, err
}
