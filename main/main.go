package main

import (
	"encoding/xml"
	"flag"
	"log"

	"github.com/zhoukk/hikisapi"
)

type DeviceInfo struct {
	XMLName         xml.Name `xml:"DeviceInfo,omitempty"`
	XMLVersion      string   `xml:"version,attr"`
	XMLNamespace    string   `xml:"xmlns,attr"`
	SubSerialNumber string   `xml:"subSerialNumber,omitempty" json:"subSerialNumber,omitempty"`
}

func main() {
	var host string
	var user string
	var pass string
	flag.StringVar(&host, "h", "192.168.1.64", "ip camera host")
	flag.StringVar(&user, "u", "admin", "ip camera username")
	flag.StringVar(&pass, "p", "123456", "ip camera password")
	flag.Parse()

	c := hikisapi.NewClient(host, user, pass)

	info := DeviceInfo{}

	err := c.Get("/ISAPI/System/deviceInfo", nil, &info)
	if err != nil {
		log.Println(err)
	} else {
		log.Printf("device: %s\n", info.SubSerialNumber)
	}
}
