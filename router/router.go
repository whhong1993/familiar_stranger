package router

import (
	jwt "fs/pkg/jwtauth"
	"github.com/gin-gonic/gin"
)

func InitSysRouter(r *gin.Engine, authMiddleware *jwt.GinJWTMiddleware) *gin.RouterGroup {
	g := r.Group("")

	sys
}
