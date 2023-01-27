package srv

import (
	"crypto/x509"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	// "github.com/gofiber/fiber/v2/middleware/monitor"
	// "github.com/gofiber/fiber/v2/middleware/proxy"
	// "github.com/valyala/fasthttp"
)

func FFF(c *fiber.Ctx) bool {
	if len(c.Context().TLSConnectionState().PeerCertificates) > 0 {
		log.Println(">>", c.OriginalURL(), c.Context().TLSConnectionState().PeerCertificates[0].DNSNames)
		certif := c.Context().TLSConnectionState().PeerCertificates[0] // первый сертификат из цепочки
		expiry := certif.NotAfter                                      // время истекает
		log.Println("время конца:", expiry.Format(time.RFC850))
		// x509.CreateRevocationList()
		ff, err := x509.ParseRevocationList(certif.SerialNumber.Bytes())
		if err != nil {
			log.Println("err:", err.Error())
		}
		log.Println("cert:", ff)
	}
	log.Println(">>", c.OriginalURL(), "Без сертификата")
	return false
}
func (sc *SrvController) InitRoutes() {
	/*
		установим Headers
	*/
	sc.App.Use(func(c *fiber.Ctx) error {
		// Set a custom header on all responses: только Post если в Proxy?
		// вероятно, что лучше выставить можно в роуте. не понятно почему тут при Get не ставится в Proxy
		// установитстргий тип  css уже не пройдет как js
		//c.Set("content-type", "text/plain; charset=utf-8") // гдето оно по умолчанию ставится
		c.Set("info2", "karamba")
		c.Response().Header.Del(fiber.HeaderServer) // удалит Header "server"
		return c.Next()
	})

	sc.App.Static("/", "/home/arkadii/ProjectsGo3/ArkNotebook/frontend/dist/spa", fiber.Static{
		Next: FFF,
	})

	// sc.App.Get("/", func(ctx *fiber.Ctx) error {
	// 	//return ctx.SendFile("../../../frontend/dist/spa/index.html")
	// 	return ctx.SendFile("/home/arkadii/ProjectsGo3/ArkNotebook/frontend/dist/spa/index.html")
	// })
	/*
		proxy.WithClient(&fasthttp.Client{
			NoDefaultUserAgentHeader: true, // true исключает заголовок User-Agent
			DisablePathNormalizing:   true, // отключает нормализацию путей, отправляет как есть.
		})
		sc.App.Get("/metrics", monitor.New(monitor.Config{Title: "Мой серверок"}))

		sc.App.Post("/api/*", sc.ProxyFunc(true))

		sc.App.Get("/apiv", func(c *fiber.Ctx) error {
			return c.SendString("Привет привет Privet")
		})
		// группа для socket.io
		socket := sc.App.Group("/socket.io/*")
		socket.Get("*", sc.ProxyFunc(true))
		socket.Post("*", sc.ProxyFunc(true))
	*/
	//sc.App.Get("/*", sc.ProxyFunc(true))

}
