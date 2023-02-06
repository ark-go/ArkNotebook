package main

import (
	"arknotebook/internal/acert"
	"arknotebook/internal/srv"
	_ "arknotebook/internal/utils"
	"log"
)

func main() {
	log.Println("старт")
	acert.CreateCA()
	acert.CreateCert()
	// запуск сервера
	srv.InitServer()
}
