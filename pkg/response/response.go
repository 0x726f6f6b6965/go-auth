package response

import (
	"time"

	"github.com/gin-gonic/gin"
)

func Response(ctx *gin.Context, code int, errString ErrorString, data interface{}) {
	ctx.JSON(code, map[string]interface{}{
		"code":        errString.Code,
		"currentTime": time.Now().UnixMilli(),
		"message":     errString.Message,
		"data":        data,
	})
}
