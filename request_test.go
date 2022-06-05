package socks5

import (
	"bytes"
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
			Error: nil,
			Message: ClientRquestMessage{
				Cmd: CmdConnect,
				Address: "123.45.3.89",
				Port: 0x0050,
				Atyp: TypeIPV4,
			},
		},
	}

	for _, test := range tests {
		var buf bytes.Buffer
		buf.Write([]byte{SOCKS5Version, test.Cmd, Reservedfield, test.AddrType})
		buf.Write(test.Address)
		buf.Write(test.port) 

		crm, err := NewClientRquestMessage(&buf)
		if err != test.Error{
			t.Fatalf("should get %s, but got %s\n",test.Error,err)
		}
		if err != nil {
			return 
		}
		if *crm !=test.Message{
			t.Fatalf("should get message %v,but got %v\n",test.Message,*crm)
		}
	}
}
