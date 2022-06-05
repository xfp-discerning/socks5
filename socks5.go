package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

//请求过程的定义错误
var (
	VesionError = errors.New("socks version not supported")
	CmdError    = errors.New("request command not supported")
	RevError    = errors.New("reserved not supported")
	AddrError   = errors.New("address not supported")
)

//socks5的版本号为0x05
const (
	SOCKS5Version = 0x05
	Reservedfield = 0x00
)

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
	if _,err := request(conn); err != nil{
		return err
	}

	//转发过程
	return nil

}

//协商过程
//报文格式 收: ver|nmethods|methods
//报文格式 发: ver|methods
func auth(conn net.Conn) error {
	clientmessage, err := NewClientAuthMEssage(conn)
	if err != nil {
		return err
	}

	// log.Println(clientmessage.Version,clientmessage.NMETHODS,clientmessage.METHODS)

	//伪代码
	// if !clientmessage.METHODS.contains(no-auth){
	// 	return noacceptable
	// }

	//only suppot no-auth
	var acceptable bool
	for _, methods := range clientmessage.METHODS {
		if methods == MethodNoAuth {
			acceptable = true
		}
	}

	// if !acceptable {
	// 	NewSererAuthMessage(conn,MethodNoAcceptable)
	// 	return errors.New("method not supported")
	// }else{
	// 	NewSererAuthMessage(conn,MethodNoAuth)
	// }
	//精简代码
	if !acceptable {
		NewSererAuthMessage(conn, MethodNoAcceptable)
		return errors.New("method not supported")
	}
	return NewSererAuthMessage(conn, MethodNoAuth)
}

//请求过程
//报文字段 收: ver|cmd|RSV|ATYP|DST.ADDR|DST.PORT
//报文字段 发: ver|REP|RSV|ATYP|BND.ADDR|BND.PORT
//ATYP=address type
//io.ReadWriteCloser为tcp连接
func request(conn io.ReadWriter) (io.ReadWriteCloser, error) {
	message, err := NewClientRquestMessage(conn)
	if err != nil {
		return nil ,err
	}
	//check if the comandis supported
	if message.Cmd != CmdConnect {
		//在REP中返回command不支持命令
	}

	if message.Atyp != TypeIPV4{
		//返回地址类型不支持
	} 
	return nil, nil 	
}
