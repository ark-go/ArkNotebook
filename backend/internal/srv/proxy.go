package srv

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/proxy"
)

func (sf *SrvController) ProxyFunc(logged ...bool) func(c *fiber.Ctx) error {
	// вернем функцию proxy , мне нужен был logger параметр :))
	return func(c *fiber.Ctx) error {
		url := sf.ProxyHost + string(c.Request().URI().RequestURI()) // без схемы и хоста
		if err := proxy.Do(c, url); err != nil {
			return err
		}
		if len(logged) > 0 {
			log.Println("proxy >>", url)
		}
		return nil
	}
}
