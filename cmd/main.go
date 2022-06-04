package main

import (
	"log"

	"github.com/xfp-discerning/socks5"
)

func main() {
	server := socks5.Socks5Sever{
		IP: "localhost",
		Port: 1080,
	}

	err := server.Run()
	if err != nil {
		log.Fatal(err)
	}
}