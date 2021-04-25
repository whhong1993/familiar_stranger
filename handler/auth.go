package handler

import (
	"github.com/mojocn/base64Captcha"
	jwt "fs/pkg/jwtauth"
)
var store = base64Captcha.DefaultMemStore

func PayloadFunc(data interface{}) jwt.MapClaims {
	if v, ok := data.(map[string]interface{}); ok {
		u, _ := v["user"].(system.SysUser)
		r, _ := v["role"].(system.SysRole)
	}
}
