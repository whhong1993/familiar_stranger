package system

import (
	"fs/handler"
	"fs/system"
	"github.com/gin-gonic/gin"
)

func SysBaseRouter(r *gin.RouterGroup) {
	r.GET("/", system.HelloWorld)
	r.GET("/info", handler.Ping)
}

func SysNoCheckRoleRouter(r *gin.RouterGroup) {
	v1 := r.Group("/api/v1")

	v1.GET("/monitor/server")
}
