package main

import (
	"smartHome/tuya"
)

func main() {
	tuya.GetToken()
	tuya.GetDevice(tuya.DeviceID)
}
