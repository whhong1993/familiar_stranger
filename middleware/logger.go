package middleware

import (
	"github.com/gin-gonic/gin"
	"fs/pkg/logger"
	"time"
)

func LoggerToFile() gin.HandlerFunc {

	return func(c *gin.Context) {
		startTime := time.Now()

		c.Next()

		endTime := time.Now()

		latencyTime := endTime.Sub(startTime)

		reqMethod := c.Request.Method

		reqUri := c.Request.RequestURI

		statusCode := c.Writer.Status()

		clientIP := c.ClientIP()

		logger.Infof(" %s %3d %13v %15s %s %s",
			startTime.Format("2021-01-01 12:00:00.9999"),
			statusCode,
			latencyTime,
			clientIP,
			reqMethod,
			reqUri,
		)
	}
}
