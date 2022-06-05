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

//客户端向socks代理服务器发送报文，
//有三个字段，VER，NMETHODS（方法数量），METHODS
//用来提供认证方法
type ClientAuthMessage struct {
	Version  byte
	NMETHODS byte
	METHODS  []Methods
}

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
