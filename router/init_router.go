package router

import (
	"fs/handler"
	"fs/middleware"
	"fs/tools"
	config2 "fs/tools/config"
	"github.com/gin-gonic/gin"
)

func InitRouter() *gin.Engine {

	r := gin.New()
	if config2.ApplicationConfig.IsHttps {
		r.Use(handler.TlsHandler())
	}
	middleware.LoggerToFile()

	authMiddleware, err := middleware.AuthInit()
	tools.HasError(err, "JWT Init Error", 200)

	Init
}
