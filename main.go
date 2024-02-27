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
	tuya.AirUp()
	r := gin.Default()
	r.GET("/airup", func(c *gin.Context) {
		tuya.AirUp()
		c.JSON(http.StatusOK, gin.H{"message": "Air Conditioner is Up"})
	})
	r.GET("/airdown", func(c *gin.Context) {
		tuya.AirDown()
		c.JSON(http.StatusOK, gin.H{"message": "Air Conditioner is Down"})
	})
	r.Run()
}
