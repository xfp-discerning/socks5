package socks5

import (
	"bytes"
	"log"
	"reflect"
	"testing"
)

//测试用例的命名规范，Testxxx
func TestNewClientAuthMessage(t *testing.T) {
	t.Run("should generate message", func(t *testing.T) {
		b := []byte{SOCKS5Version, 2, 0x00, 0x01}
		//依赖注入？？？？？
		r := bytes.NewReader(b)

		message, err := NewClientAuthMEssage(r)
		if err != nil {
			t.Fatalf("want err = nil, but got err = %s\n", err)
		}
		if message.Version != SOCKS5Version {
			t.Fatalf("want %d but got %d\n", SOCKS5Version, message.Version)
		}
		if message.NMETHODS != 2 {
			t.Fatalf("want nmethods = 2, but got %d\n", message.NMETHODS)
		}
		//使用反射对比切片，slice只能和nil用=对比
		if !reflect.DeepEqual(message.METHODS, []byte{0x00, 0x01}) {
			t.Fatalf("want methods : %v, but got : %v\n", []byte{0x00, 0x01}, message.METHODS)
		}
	})

	//失败样例
	t.Run("methods length is shorter", func(t *testing.T) {
		b := []byte{SOCKS5Version, 2, 0x00} //methods只有一个
		//依赖注入？？？？？
		r := bytes.NewReader(b)

		_, err := NewClientAuthMEssage(r)
		if err == nil {
			t.Fatalf("should get error != nil, but got nil")
		}
	})
}

func TestNewServerAuthMessage(t *testing.T) {
	t.Run("should pass", func(t *testing.T) {
		var buf bytes.Buffer //依赖注入
		err := NewSererAuthMessage(&buf, MethodNoAuth)
		if err != nil {
			t.Fatalf("want get nil, but got err:%s\n", err)
		}

		got := buf.Bytes()
		//slice对比用反射
		if !reflect.DeepEqual(got, []byte{SOCKS5Version, MethodNoAuth}) {
			t.Fatalf("should %v,but got %v\n", []byte{SOCKS5Version, MethodNoAuth}, got)
		}
	})
}

func TestNewClientPasswordMessage(t *testing.T) {
	t.Run("valid password auth message", func(t *testing.T) {
		username, password := "admin", "123456"
		var buf bytes.Buffer
		buf.Write([]byte{PasswordAuthVersion, 5})
		buf.WriteString("username")
		buf.WriteByte(6)
		buf.WriteString("password")
		cpm, err := NewClientPasswordMessage(&buf)
		if err != nil {
			log.Fatalf("want err = nil, but got err :%s\n", err)
		}
		want := ClientPasswordMessage{
			name:     username,
			password: password,
		}
		if *cpm != want {
			t.Fatalf("want :%v, but got %v\n", want, *cpm)
		}
	})
}

//note:测试时，全局不能报错
