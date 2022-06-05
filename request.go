package socks5

import (
	"io"
	"net"
)

type ClientRquestMessage struct {
	// Version byte
	Cmd     Command
	Address string
	Port    uint16
	Atyp  AddressType
	//不重要信息可以做省略
}

type Command = byte

const (
	CmdConnect Command = 0x01
	CmdBind    Command = 0x02
	CmdUDP     Command = 0x03
)

const (
	IPV4Length = 4
	IPV6Length = 6
	PortLength = 2
)

type AddressType = byte

const (
	TypeIPV4   AddressType = 0x01
	TypeDomain AddressType = 0x03
	TypeIPV6   AddressType = 0x04
)

func NewClientRquestMessage(conn io.Reader) (*ClientRquestMessage, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	version, comand, rev, atyp := buf[0], buf[1], buf[2], buf[3]
	if version != SOCKS5Version {
		return nil, VesionError
	}
	if comand != CmdUDP && comand != CmdBind && comand != CmdConnect {
		return nil, CmdError
	}
	if rev != Reservedfield {
		return nil, RevError
	}
	if atyp != TypeIPV4 && atyp != TypeIPV6 && atyp != TypeDomain {
		return nil, AddrError
	}

	message := ClientRquestMessage{
		Cmd: comand,
		Atyp: atyp,
	}

	//read address
	switch atyp {
	case TypeIPV6:
		buf = make([]byte, IPV6Length)
		fallthrough //执行下一个分支，节省代码量
	case TypeIPV4:
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		b := net.IP(buf)
		message.Address = b.String()
	case TypeDomain: //第一个字节代表的域名的长度
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return nil, err
		}
		domainlength := buf[0]
		if domainlength > TypeIPV4 {
			buf = make([]byte, domainlength)
		}
		if _, err := io.ReadFull(conn, buf[:domainlength]); err != nil {
			return nil, err
		}
		message.Address = string(buf[:domainlength])   //和视频代码有歧义
	}

	//read port
	if _, err := io.ReadFull(conn, buf[:PortLength]); err != nil {
		return nil, err
	}
	message.Port = uint16(buf[0])<<8 + uint16(buf[1])//左移8位
	return &message, nil
}

type RplyType = byte

const(
	ReplySuccess RplyType = iota
	ReplyServerFailure
	ReplyConnectionNotAllowed
	ReplyNetworkUnreachable
	ReplyHostUnreachable
	ReplyConnectionRefused
	ReplyTTLExpired
	ReplyCommandNotSupported
	ReplyAddressTypeNotSupported
)

func WriteRequestSuccessMessage(conn io.Writer) error {
	// conn.Write([]byte)
	return nil
}