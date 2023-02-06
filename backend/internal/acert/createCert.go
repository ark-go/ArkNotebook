package acert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func CreateCert() error {
	// ca, err := os.ReadFile("/usr/certs/out/certTestCA.crt")
	// if err != nil {
	// 	log.Println("Не прочитать сертификат CA")
	// 	return err
	// }
	// caPrivKey, err := os.ReadFile("/usr/certs/out/certTestCA.key")
	// if err != nil {
	// 	log.Println("Не прочитать ключ (приватный) CA")
	// 	return err
	// }
	ca, caPrivKey, err := LoadX509KeyPair("/usr/certs/out/certTestCA.crt", "/usr/certs/out/certTestCA.key")
	if err != nil {
		log.Println("Не прочитатьCA", err)
		return err
	}
	// -----  сертификат
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Arkadii, INC."},
			Country:       []string{"RU"},
			Province:      []string{"кхе"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"194016"},
		},
		//IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"arkadii.ru"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	// Private key
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	// создаем
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	///////////////
	// Закодируем сертификат в PEM
	clientPEM := new(bytes.Buffer)
	pem.Encode(clientPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err := os.WriteFile("/usr/certs/out/certTestClient.crt", clientPEM.Bytes(), 0777); err != nil {
		return err
	}

	// закодируем приватный ключ в PEM
	clientPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(clientPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err := os.WriteFile("/usr/certs/out/certTestClient.key", clientPrivKeyPEM.Bytes(), 0777); err != nil {
		return err
	}
	return nil
}

// читаем файлы crt / key
func LoadX509KeyPair(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cf, err := os.ReadFile(certFile)
	if err != nil {
		log.Println("cfload:", err.Error())
		return nil, nil, err
	}

	kf, err := os.ReadFile(keyFile)
	if err != nil {
		log.Println("kfload:", err.Error())
		return nil, nil, err
	}
	cpb, cr := pem.Decode(cf) //!  cpb  не nil
	log.Println("pem decode", string(cr))
	kpb, kr := pem.Decode(kf)
	log.Println("pem decode 2", string(kr))
	crt, err := x509.ParseCertificate(cpb.Bytes)

	if err != nil {
		log.Println("parsex509:", err.Error())
		return nil, nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(kpb.Bytes)
	if err != nil {
		log.Println("parsekey:", err.Error())
		return nil, nil, err
	}
	return crt, key, nil
}
