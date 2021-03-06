package socks

import "errors"

// Context 服务端请求处理的上下文
type Context interface {
	Set(key string, val interface{})
	Get(key string) (interface{}, error)
	Clean()
}

// NewContext 创建上下文
func NewContext() Context {
	return &context{
		vals: make(map[string]interface{}),
	}
}

type context struct {
	vals map[string]interface{}
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
}
