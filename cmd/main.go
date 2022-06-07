package main

import (
	"log"

	"github.com/xfp-discerning/socks5"
)

func main() {
	//用map模拟数据库
	db := map[string]string{
		"jack": "123456",
		"李四":   "234567",
	}
	server := socks5.Socks5Sever{
		IP:   "localhost",
		Port: 1080,
		Config: &socks5.Config{
			AuthMethod: socks5.MethodPassword,
			PasswordChecker: func(username, password string) bool {
				wantPassword, ok := db[username]
				if !ok {
					return false
				}
				if wantPassword != password {
					return false
				}
				return true
			},
		},
	}

	err := server.Run()
	if err != nil {
		log.Fatal(err)
	}
}
