package socks

import (
	"errors"
	"net"
)

// Context 服务端请求处理的上下文
type Context interface {
	GetConn() net.Conn
	Set(key string, val interface{})
	Get(key string) (interface{}, error)
	Clean()
}
type context struct {
	conn net.Conn
	vals map[string]interface{}
}

// NewContext 创建上下文
func NewContext(conn net.Conn) Context {
	return &context{
		conn: conn,
		vals: make(map[string]interface{}),
	}
}

func (ctx *context) GetConn() net.Conn {
	return ctx.conn
}

func (ctx *context) Set(key string, val interface{}) {
	ctx.vals[key] = val
}

func (ctx *context) Get(key string) (interface{}, error) {
	val, found := ctx.vals[key]
	if !found {
		return nil, errors.New("get context value failed")
	}
	return val, nil
}

func (ctx *context) Clean() {
	for key := range ctx.vals {
		delete(ctx.vals, key)
	}
	ctx.conn = nil
}
