package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	type Campground struct {
		Comment   string   `xml:",comment"`
		InnerXml  string   `xml:",innerxml"` //Accumulates the raw XML into the field
		InnerAttr []string `xml:",any,attr"` //Places an attribute not handled by the previous rule into the field
	}
	// Open our xmlFile
	xmlFile, err := os.Open(os.Args[1])
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Successfully Opened server.xml")
	// defer the closing of our xmlFile so that we can parse it later on
	defer xmlFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, _ := ioutil.ReadAll(xmlFile)

	var server struct {
		Comment   string       `xml:",comment"`
		InnerXml  string       `xml:",innerxml"` //Accumulates the raw XML into the field
		InnerAttr []string     `xml:",any,attr"` //Places an attribute not handled by the previous rule into the field
		InnerElem []Campground `xml:",any"`
	}
	if err := xml.Unmarshal([]byte(byteValue), &server); err != nil {
		log.Fatal(err)
	}

	fmt.Printf(server.Comment)
	for _, el := range server.InnerElem {
		fmt.Printf(el.Comment)
	}

}
