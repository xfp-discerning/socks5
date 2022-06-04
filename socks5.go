package socks5

import (
	"fmt"
	"log"
	"net"
)

//socks5的版本号为0x05
const SOCKS5Version = 0x05

//server的功能
type Server interface {
	Run() error
}

//实现Server
type Socks5Sever struct {
	IP   string
	Port int
}

//Server是用来处理客户端发来消息的循环
func (s *Socks5Sever) Run() error {
	address := fmt.Sprintf("%s:%d", s.IP, s.Port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("connection failed ,err:", err)
		}

		//开协程,包上函数，可以做错误处理
		go func() {
			defer conn.Close() //使用defer保证资源的回收
			err := handleconnection(conn)
			if err != nil {
				log.Println("handle connection failed ,err:", err)
			}
		}()

	}
}

//处理连接上的请求
func handleconnection(conn net.Conn) error {
	//协商过程
	if err := auth(conn); err != nil {
		return err
	}

	//请求过程

	//转发过程
	return nil

}

func auth(conn net.Conn) error {
	clientmessage, err := NewClientAuthMEssage(conn)
	if err != nil {
		return err
	}

	// log.Println(clientmessage.Version,clientmessage.NMETHODS,clientmessage.METHODS)

	//only suppot no-auth
	//伪代码
	// if 	!clientmessage.METHODS.contains(no-auth){
	// 	return noacceptable
	// }
	var accept bool
	for _, methods := range clientmessage.METHODS {
		if methods == MethodNoAuth {
			accept = true
		}
	}

	return nil
}
