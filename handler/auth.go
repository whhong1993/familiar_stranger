package handler

import (
	jwt "fs/pkg/jwtauth"
	"github.com/mojocn/base64Captcha"
)

var store = base64Captcha.DefaultMemStore

func PayloadFunc(data interface{}) jwt.MapClaims {
	if v, ok := data.(map[string]interface{}); ok {
		u, _ := v["user"].(system.SysUser)
		r, _ := v["role"].(system.SysRole)
	}
}
