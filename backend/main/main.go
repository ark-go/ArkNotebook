package main

import (
	"arknotebook/internal/srv"
	_ "arknotebook/internal/utils"
	"log"
)

func main() {
	log.Println("старт")

	// запуск сервера
	srv.InitServer()
}
