package socks5

import (
	"errors"
	"io"
)

type Methods = byte

const (
	MethodNoAuth       Methods = 0x00
	MethodGSSAPI       Methods = 0x01
	MethodPassword     Methods = 0x02
	MethodNoAcceptable Methods = 0xff
)

const (	
	PasswordAuthVersion = 0x01
	//密码验证，服务器返回的status
	Passauthsuccess = 0x00
	Passauthfail = 0x01//任意非零都表错误
)

//客户端向socks代理服务器发送报文，
//有三个字段，VER，NMETHODS（方法数量），METHODS
//用来提供认证方法
type ClientAuthMessage struct {
	Version  byte
	NMETHODS byte
	METHODS  []Methods
}

type ClientPasswordMessage struct {
	name     string
	password string
}

//服务器发消息的一个封装
func NewSererAuthMessage(conn io.Writer, method Methods) error {
	buf := []byte{SOCKS5Version, method}
	_, err := conn.Write(buf)
	// if err != nil {
	// 	return err
	// }
	// return nil
	return err
}

//func NewClientAuthMEssage(conn net.conn) (*ClientAuthMessage, error)
//这里使用io.Reader而不使用net.conn是为了方便测试，测试中建立一个连接相对麻烦
func NewClientAuthMEssage(conn io.Reader) (*ClientAuthMessage, error) {
	//读取version和nmethods
	buf := make([]byte, 2)
	//比较繁琐
	// count := 0
	// for{
	// 	n, err := conn.Read(buf)
	// 	count += n
	// }
	//ReandFull应该传入io.Reader的接口类型参数
	//但是conn本身也是接口，且实现了Read()方法
	//所以，conn也可做为io.Reader类型传入
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	//validate version
	if buf[0] != SOCKS5Version {
		return nil, errors.New("protocal vesion not supported")
	}
	//Read Methods
	nmethods := buf[1]
	buf = make([]byte, nmethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	return &ClientAuthMessage{
		Version:  SOCKS5Version,
		NMETHODS: nmethods,
		METHODS:  buf,
	}, nil
}

//密码认证，收到客户端的报文，格式：ver(1)、ulen(1)、uname(1-255)、plen(1)、password(1-255)
func NewClientPasswordMessage(conn io.Reader) (*ClientPasswordMessage, error) {
	//read version and uernamelenth
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	version, usernamelen := buf[0], buf[1]
	if version != PasswordAuthVersion {
		return nil, PasswordAuthVersionError
	}
	//read name
	buf = make([]byte, usernamelen+1)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	username, passwordlen := string(buf[:len(buf)-1]), buf[len(buf)-1]

	//test报错？？？
	// username, passwordlen := buf[:len(buf)-1], buf[len(buf)-1]

	if len(buf) < int(passwordlen) {
		buf = make([]byte, passwordlen)
	}
	if _, err = io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	pword := buf[:int(passwordlen)]

	return &ClientPasswordMessage{
		name:     username,
		password: string(pword),
	}, nil

	//test报错？？？此时username==12345
	// return &ClientPasswordMessage{
	// 	name:     username,
	// 	password: string(pword),
	// }, nil

}

//代理服务器在密码验证阶段返回报文
//格式为ver、status
func WriteServerPasswordMessage(conn io.Writer, status byte) error {
	_, err := conn.Write([]byte{PasswordAuthVersion, status})
	return err
}
