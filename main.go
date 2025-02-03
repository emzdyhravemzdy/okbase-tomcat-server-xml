package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
)

func main() {
	//<Resource name="UserDatabase" auth="Container"
	//              type="org.apache.catalina.UserDatabase"
	//              description="User database that can be updated and saved"
	//              factory="org.apache.catalina.users.MemoryUserDatabaseFactory"
	//              pathname="conf/tomcat-users.xml" />
	type resource struct {
		XMLName     xml.Name `xml:"Resource"`
		Name        string   `xml:"name,attr"`
		Auth        string   `xml:"auth,attr"`
		Type        string   `xml:"type,attr"`
		Description string   `xml:"description,attr"`
		Factory     string   `xml:"factory,attr"`
		Pathname    string   `xml:"pathname,attr"`
	}
	type globalNamingResources struct {
		XMLName  xml.Name `xml:"GlobalNamingResources"`
		Resource resource `xml:"Resource"`
	}
	//<Listener className="org.apache.catalina.startup.VersionLoggerListener" />
	type listener struct {
		ClassName string `xml:"className,attr"`
	}
	// <Connector port="8080" protocol="HTTP/1.1"
	//               connectionTimeout="20000"
	//               redirectPort="8443"
	//               maxParameterCount="1000"
	//               />
	type connector struct {
		XMLName           xml.Name `xml:"Connector"`
		Port              string   `xml:"port,attr"`
		Protocol          string   `xml:"protocol,attr"`
		ConnectionTimeout string   `xml:"connectionTimeout,attr"`
		RedirectPort      string   `xml:"redirectPort,attr"`
		MaxParameterCount int      `xml:"maxParameterCount,attr"`
	}
	//<Realm className="org.apache.catalina.realm.UserDatabaseRealm" resourceName="UserDatabase"/>
	type realmInner struct {
		XMLName      xml.Name `xml:"Realm"`
		ClassName    string   `xml:"className,attr"`
		ResourceName string   `xml:"resourceName,attr"`
	}
	//<Realm className="org.apache.catalina.realm.LockOutRealm">
	type realm struct {
		XMLName   xml.Name   `xml:"Realm"`
		ClassName string     `xml:"className,attr"`
		Realm     realmInner `xml:"Realm"`
	}
	//<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
	//	               prefix="localhost_access_log" suffix=".txt"
	//	               pattern="%h %l %u %t &quot;%r&quot; %s %b" />
	type valve struct {
		XMLName   xml.Name `xml:"Valve"`
		ClassName string   `xml:"className,attr"`
		Directory string   `xml:"directory,attr"`
		Prefix    string   `xml:"prefix,attr"`
		Suffix    string   `xml:"suffix,attr"`
		Pattern   []byte   `xml:"pattern,attr"`
	}
	//<Host name="localhost"  appBase="webapps" unpackWARs="true" autoDeploy="true">
	type host struct {
		XMLName    xml.Name `xml:"Host"`
		Name       string   `xml:"name,attr"`
		AppBase    string   `xml:"appBase,attr"`
		UnpackWARs bool     `xml:"unpackWARs,attr"`
		AutoDeploy bool     `xml:"autoDeploy,attr"`
		Valve      valve    `xml:"Valve"`
	}
	//<Engine name="Catalina" defaultHost="localhost">
	type engine struct {
		XMLName     xml.Name `xml:"Engine"`
		Name        string   `xml:"name,attr"`
		DefaultHost string   `xml:"defaultHost,attr"`
		Realm       realm    `xml:"Realm"`
		Host        host     `xml:"Host"`
	}
	//<Service name="Catalina">
	type service struct {
		XMLName   xml.Name  `xml:"Service"`
		Name      string    `xml:"name,attr"`
		Connector connector `xml:"Connector"`
		Engine    engine    `xml:"Engine"`
	}
	//<Server port="8005" shutdown="SHUTDOWN">
	type server struct {
		XMLName               xml.Name              `xml:"Server"`
		Port                  string                `xml:"port,attr"`
		Shutdown              string                `xml:"shutdown,attr"`
		Listeners             []listener            `xml:"Listener"`
		GlobalNamingResources globalNamingResources `xml:"GlobalNamingResources"`
		Service               service               `xml:"Service"`
	}

	var xmlReadFile *os.File = nil
	var err error = nil

	// Open our xmlFile
	xmlReadFile, err = os.Open(os.Args[1])
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Successfully Opened server.xml")
	// defer the closing of our xmlFile so that we can parse it later on
	defer func(xmlFile *os.File) {
		err := xmlFile.Close()
		if err != nil {
			log.Fatal(err)
			return
		}
	}(xmlReadFile)

	var xmlReadBytes []byte = nil
	// read our opened xmlFile as a byte array.
	if xmlReadBytes, err = io.ReadAll(xmlReadFile); err != nil {
		log.Fatal(err)
		return
	}

	var serverXml server

	if err = xml.Unmarshal(xmlReadBytes, &serverXml); err != nil {
		log.Fatal(err)
		return
	}

	var xmlWriteFile *os.File = nil
	filePath := os.Args[2]
	xmlWriteFile, err = os.Create(filePath)
	if err != nil {
		log.Fatal(err)
		return
	}
	if _, err = xmlWriteFile.WriteString(xml.Header); err != nil {
		log.Fatal(err)
		return
	}
	var xmlWriteBytes []byte = nil
	xmlWriteBytes, err = xml.MarshalIndent(&serverXml, "", "  ")

	var regex *regexp.Regexp = nil
	if regex, err = regexp.Compile(`></[A-Za-z0-9_]+>`); err != nil {
		log.Fatal(err)
		return
	}

	var xmlRegexBytes []byte = nil
	xmlRegexBytes = regex.ReplaceAll(xmlWriteBytes, []byte(" />"))

	xmlString := string(xmlRegexBytes)

	var escapeString = map[string]string{
		"&#34;": "&quot;",
		"&#39;": "&apos;",
	}

	for k, v := range escapeString {
		xmlString = strings.Replace(xmlString, k, v, -1)
	}

	if _, err = xmlWriteFile.WriteString(xmlString); err != nil {
		log.Fatal(err)
		return
	}

	if err = xmlWriteFile.Close(); err != nil {
		log.Fatal(err)
		return
	}
}
