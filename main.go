package main

import (
	"smartHome/tuya"
)

var (
	Token string
)

func main() {
	tuya.Main()
	tuya.GetDevice(tuya.DeviceID)
}
