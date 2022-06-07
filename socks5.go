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
	VesionError              = errors.New("socks version not supported")
	CmdError                 = errors.New("request command not supported")
	RevError                 = errors.New("reserved not supported")
	AddrError                = errors.New("address not supported")
	PasswordAuthVersionError = errors.New("password auth version supported")
	PasswordAthufailureError = errors.New("athu fail uername/password")
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
	IP     string
	Port   int
	Config *Config
}

//Config的默认配置
func initConfig(config *Config) error {
	if config.AuthMethod == MethodPassword && config.PasswordChecker == nil {
		return errors.New("error checker not set")
	}
	return nil
}

type Config struct {
	AuthMethod      Methods
	PasswordChecker func(username, password string) bool
}

//Server是用来处理客户端发来消息的循环
func (s *Socks5Sever) Run() error {
	//init
	if err := initConfig(s.Config); err != nil {
		return err
	}
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
			err := handleconnection(conn, s.Config)
			if err != nil {
				log.Println("handle connection failed ,err:", err)
			}
		}()

	}
}

//处理连接上的请求
func handleconnection(conn net.Conn, config *Config) error {
	//协商过程
	if err := auth(conn, config); err != nil {
		return err
	}

	//请求过程
	targetConn, err := request(conn)
	if err != nil {
		return err
	}

	//转发过程
	return forward(conn, targetConn)

}

//协商过程
//报文格式 收: ver|nmethods|methods
//报文格式 发: ver|methods
func auth(conn net.Conn, config *Config) error {
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
	// var acceptable bool
	// for _, methods := range clientmessage.METHODS {
	// 	if methods == MethodNoAuth {
	// 		acceptable = true
	// 	}
	// }
	// if !acceptable {
	// 	NewSererAuthMessage(conn, MethodNoAcceptable)
	// 	return errors.New("method not supported")
	// }
	// return NewSererAuthMessage(conn, MethodNoAuth)

	//check if the auth method is supported
	var acceptable bool
	for _, methods := range clientmessage.METHODS {
		if methods == MethodNoAuth {
			acceptable = true
		}
	}
	if !acceptable {
		NewSererAuthMessage(conn, MethodNoAcceptable)
		return errors.New("method not supported")
	}
	if err := NewSererAuthMessage(conn, config.AuthMethod); err != nil {
		return err
	}
	if config.AuthMethod == MethodPassword {
		cpm, err2 := NewClientPasswordMessage(conn)
		if err2 != nil {
			return err2
		}
		if !config.PasswordChecker(cpm.name, cpm.password) {
			//认证失败
			//认证失败后，conn会断开，可以忽略这一错误
			WriteServerPasswordMessage(conn, Passauthfail)
			return PasswordAthufailureError
		}
		if err := WriteServerPasswordMessage(conn, Passauthsuccess); err != nil {
			return err
		}
	}
	return nil
}

//请求过程
//报文字段 收: ver|cmd|RSV|ATYP|DST.ADDR|DST.PORT
//报文字段 发: ver|REP|RSV|ATYP|BND.ADDR|BND.PORT
//ATYP=address type
//io.ReadWriteCloser为tcp连接
func request(conn io.ReadWriter) (io.ReadWriteCloser, error) {
	message, err := NewClientRquestMessage(conn)
	if err != nil {
		return nil, err
	}
	//check if the comandis supported
	if message.Cmd != CmdConnect {
		//在REP中返回command不支持命令
		return nil, WriteRequestFailureMessage(conn, ReplyCommandNotSupported)
	}

	if message.Atyp != TypeIPV4 {
		//返回地址类型不支持
		return nil, WriteRequestFailureMessage(conn, ReplyAddressTypeNotSupported)
	}

	//请求访问远程目标tcp服务
	//message.Address:port
	address := fmt.Sprintf("%s:%d", message.Address, message.Port)
	targetConn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, WriteRequestFailureMessage(conn, ReplyConnectionRefused)
	}

	//send successful connection
	addrValue := targetConn.LocalAddr()
	addr := addrValue.(*net.TCPAddr) //类型断言
	return targetConn, WriteRequestSuccessMessage(conn, addr.IP, uint16(addr.Port))
}

func forward(conn io.ReadWriter, targetconn io.ReadWriteCloser) error {
	defer targetconn.Close()
	go io.Copy(conn, targetconn)
	_, err := io.Copy(targetconn, conn)
	return err
}
