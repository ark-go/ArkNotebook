package srv

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/gofiber/fiber/v2"
)

type SrvController struct {
	// собственно сам fiber
	App *fiber.App
	// адрес перенаправления запроса
	ProxyHost string
}

func InitServer() {

	sc := &SrvController{
		ProxyHost: "http://127.0.0.1:8037",
	}

	if fiber.IsChild() == true {
		log.Println("Старт  ребенком --------------->")
	} else {
		log.Println("Старт --------------->")
	}
	sc.App = fiber.New(fiber.Config{
		// Если установлено значение true, это порождает несколько процессов Go, прослушивающих один и тот же порт.
		//Prefork: true,
		// Если установлено значение true, включает маршрутизацию с учетом регистра. Например. '/FoO' и '/foo'
		CaseSensitive: false,
		// Если установлено значение true, маршрутизатор рассматривает «/foo» и «/foo/» как разные
		StrictRouting: false,
		// header - server name
		ServerHeader: "Ark Fi",
		AppName:      "ArkNotepad v1.0.1",
		//DisableStartupMessage: true, // картинка при старте
	})
	// micro := fiber.New(fiber.Config{
	// 	ServerHeader: "Копия",
	// })
	// sc.App.Mount("/apix2", micro)
	// micro.Get("/apix", func(c *fiber.Ctx) error {
	// 	return c.SendString("Привет привет Micro")
	// })

	sc.InitRoutes()
	sc.App.Hooks().OnListen(func() error {
		log.Println("Сервер запущен")
		return nil
	})
	sc.App.Hooks().OnShutdown(func() error {
		log.Println("Shutdown server")
		return nil
	})
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	serverShutdown := make(chan struct{})
	go func(shutd chan struct{}) {
		_ = <-c
		log.Println("Попросим сервер заткнуться..")
		if err := sc.App.ShutdownWithTimeout(5 * time.Second); err != nil {
			log.Println("Закрыли но, не очень хорошо:", err)
		}

		shutd <- struct{}{}
	}(serverShutdown)

	cert, err := tls.LoadX509KeyPair(os.Getenv("SERVER_CERT"), os.Getenv("SERVER_CERT_PRIVKEY"))
	if err != nil {
		log.Println("tls error:", err.Error())
	}
	if os.Getenv("SERVER_TLS") == "true" {

		log.Println("tls включен")
		var caCertPool *x509.CertPool
		caCertPool = x509.NewCertPool()
		caCert, err := ioutil.ReadFile("/usr/certs/out/ArkadiiCA.crt")
		if err != nil {
			log.Fatal("Error opening cert file", "-- -", ", error ", err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
		_ = cert
		ln, _ := net.Listen("tcp", os.Getenv("SERVER_ADDR")+":"+os.Getenv("SERVER_PORT"))
		//--
		getClientValidator := func(helloInfo *tls.ClientHelloInfo) func([][]byte, [][]*x509.Certificate) error {
			return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				//copied from the default options in src/crypto/tls/handshake_server.go, 680 (go 1.11)
				//but added DNSName
				opts := x509.VerifyOptions{
					Roots:         caCertPool,
					CurrentTime:   time.Now(),
					Intermediates: x509.NewCertPool(),
					KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning},
					// гдето в сертификате CA должен быть список доменов или IP адресов ?? хз
					//DNSName:       strings.Split(helloInfo.Conn.RemoteAddr().String(), ":")[0],
				}
				// helloInfo.ServerName  - что запрашивал клиент адрес какой ? ip - не показывает
				log.Println("vv:", opts.DNSName, ">", helloInfo.ServerName, ">", helloInfo.Conn.RemoteAddr().String())
				_, err := verifiedChains[0][0].Verify(opts)
				return err
			}
		}
		//--
		var tlsConf *tls.Config
		tlsConf = &tls.Config{
			ServerName: "arkadii.ru",
			// MinVersion: tls.VersionTLS12,
			// ClientAuth: tls.RequireAndVerifyClientCert,
			// //ClientAuth: tls.RequireAnyClientCert, //tls.NoClientCert,
			// ClientCAs: caCertPool,
			Certificates: []tls.Certificate{
				cert,
			},

			// все это нужно чтоб проверить (сертификат SAN) разрешенный IP (домен) клиента - но с чем ?? пока не знаю
			GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
				serverConf := &tls.Config{
					Certificates:          []tls.Certificate{cert},
					MinVersion:            tls.VersionTLS12,
					ClientAuth:            tls.RequireAndVerifyClientCert,
					ClientCAs:             caCertPool,
					VerifyPeerCertificate: getClientValidator(hi),
				}
				return serverConf, nil
			},
		}
		ln = tls.NewListener(ln, tlsConf)
		sc.App.Listener(ln)

	} else {
		log.Println("без tls")

		if err := sc.App.Listen(os.Getenv("SERVER_ADDR") + ":" + os.Getenv("SERVER_PORT")); err != nil {
			log.Panic(err)
		}
	}
	<-serverShutdown
	log.Println("Running cleanup tasks...")

}
