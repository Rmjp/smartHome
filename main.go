package main

import (
	"net/http"

	"smartHome/tuya"

	"github.com/gin-gonic/gin"
)

var (
	Token string
)

func main() {
	tuya.Main()
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.Run()
}
