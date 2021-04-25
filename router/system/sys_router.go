package system

import (
	"github.com/gin-gonic/gin"
	"fs/handler"
	"fs/system"
)

func SysBaseRouter(r *gin.RouterGroup) {
	r.GET("/", system.HelloWorld)
	r.GET("/info", handler.Ping)
}

func SysNoCheckRoleRouter(r *gin.RouterGroup) {
	v1 := r.Group("/api/v1")

	v1.GET("/monitor/server")
}

