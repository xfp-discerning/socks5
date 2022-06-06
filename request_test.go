package socks5

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestNewClientRquestMessage(t *testing.T) {
	tests := []struct {
		Cmd      Command
		AddrType AddressType
		Address  []byte
		port     []byte
		Error    error
		Message  ClientRquestMessage
	}{
		{
			Cmd:      CmdConnect,
			AddrType: TypeIPV4,
			Address:  []byte{123, 45, 3, 89},
			port:     []byte{0x00, 0x50},
			Error:    nil,
			Message: ClientRquestMessage{
				Cmd:     CmdConnect,
				Address: "123.45.3.89",
				Port:    0x0050,
				Atyp:    TypeIPV4,
			},
		},
	}

	for _, test := range tests {
		var buf bytes.Buffer
		buf.Write([]byte{SOCKS5Version, test.Cmd, Reservedfield, test.AddrType})
		buf.Write(test.Address)
		buf.Write(test.port)

		crm, err := NewClientRquestMessage(&buf)
		if err != test.Error {
			t.Fatalf("should get %s, but got %s\n", test.Error, err)
		}
		if err != nil {
			return
		}
		if *crm != test.Message {
			t.Fatalf("should get message %v,but got %v\n", test.Message, *crm)
		}
	}

}

func TestWriteRequestSuccessMessage(t *testing.T) {
	var buf bytes.Buffer
	ip := net.IP([]byte{123, 234, 34, 56})
	err := WriteRequestSuccessMessage(&buf, ip, 1081)
	if err != nil {
		t.Fatalf("want err=nil, but got err :%s\n", err)
	}
	want := []byte{SOCKS5Version, ReplySuccess, Reservedfield, TypeIPV4, 123, 234, 34, 56, 0x04, 0x39}
	got := buf.Bytes()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("want :%v,but got %v\n", want, got)
	}
}
