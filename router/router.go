package router

import (
	"github.com/gin-gonic/gin"
	jwt "fs/pkg/jwtauth"
)

func InitSysRouter(r *gin.Engine, authMiddleware *jwt.GinJWTMiddleware) *gin.RouterGroup {
	g := r.Group("")

	sys
}
