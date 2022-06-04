package socks5

import (
	"bytes"
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
			t.Fatalf("want err = nil, but got err = %s\n",err)
		}
		if message.Version !=SOCKS5Version{
			t.Fatalf("want %d but got %d\n",SOCKS5Version,message.Version)
		}
		if message.NMETHODS != 2{
			t.Fatalf("want nmethods = 2, but got %d\n",message.NMETHODS)
		}
		//使用反射对比切片，slice只能和nil用=对比
		if !reflect.DeepEqual(message.METHODS,[]byte{0x00,0x01}){
			t.Fatalf("want methods : %v, but got : %v\n",[]byte{0x00,0x01},message.METHODS)
		}
	})

	//失败样例
	t.Run("methods length is shorter",func(t *testing.T) {
		b := []byte{SOCKS5Version, 2, 0x00}//methods只有一个
		//依赖注入？？？？？
		r := bytes.NewReader(b) 
		
		_, err := NewClientAuthMEssage(r)
		if err==nil{
			t.Fatalf("should get error != nil, but got nil")
		}
	})
}
