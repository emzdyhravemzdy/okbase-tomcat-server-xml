package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
)

func main() {
	//<Connector port="8088" protocol="HTTP/1.1"
	//               connectionTimeout="20000"
	//               redirectPort="443" />
	//
	// <Connector protocol="org.apache.coyote.http11.Http11AprProtocol"
	//               port="8443" SSLEnabled="true" secure="true" scheme="https"
	//               SSLProtocol="TLSv1.2+TLSv1.3"
	//               SSLCipherSuite="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
	//               SSLHonorCipherOrder="true" SSLDisableCompression="true"
	//               SSLCertificateFile="${catalina.home}/conf/certificate.crt"
	//               SSLCertificateKeyFile="${catalina.home}/conf/private.key"
	//               SSLCertificateChainFile="${catalina.home}/conf/ca.crt"
	//               SSLPassword=""
	//               disableUploadTimeout="true"
	//               maxThreads="200" acceptCount="100"
	//               maxHttpHeaderSize="49152"/>
	//
	//<!-- PFX -->
	//    <Connector port="8443" protocol="org.apache.coyote.http11.Http11AprProtocol"
	//               maxThreads="150" SSLEnabled="true">
	//        <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol" />
	//        <SSLHostConfig protocols="TLSv1.2,TLSv1.3" ciphers="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256" >
	//            <Certificate certificateKeystoreFile="${catalina.home}/conf/certificate.pfx"
	//                         certificateKeystorePassword="tomcat"
	//                         certificateKeystoreType="PKCS12"
	//            />
	//     </SSLHostConfig>
	//  </Connector>
	//
	//      <Host name="localhost"  appBase="webapps"
	//            unpackWARs="true" autoDeploy="false">
	//
	// <Valve className="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false" />
	//
	//<!--   TOHLE ODKOMENTOVAT POKUD TO BEZI ZA PROXY
	//        <Valve className="org.apache.catalina.valves.RemoteIpValve"
	//        internalProxies="192\.168\.250\.64"
	//        remoteIpHeader="x-forwarded-for"
	//        proxiesHeader="x-forwarded-by"
	//        protocolHeader="x-forwarded-proto"/>
	//
	//        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
	//        prefix="localhost_access_log" suffix=".txt"
	//        pattern="%{org.apache.catalina.AccessLog.RemoteAddr}r %h %l %u %t &quot;%r&quot; %s %b" resolveHosts="false"/>
	//-->
	//
	//<!--  TOHLE ZAKOMENTOVAT POKUD TO BEZI ZA PROXY  -->
	//        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
	//        prefix="localhost_access_log" suffix=".txt"
	//        pattern="%h %l %u %t &quot;%r&quot; %s %b" />
	if len(os.Args) != 3 {
		log.Fatal(errors.New("insufficient number of arguments (input file and output file)"))
		return

	}
	fileInputPath := os.Args[1]
	fileOutputPath := os.Args[2]

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

	type okbaseServer struct {
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
	xmlReadFile, err = os.Open(fileInputPath)
	// if we os.Open returns an error then handle it
	if err != nil {
		log.Fatal(err)
		return
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

	fmt.Println("Successfully Read server.xml")
	var serverXml server

	if err = xml.Unmarshal(xmlReadBytes, &serverXml); err != nil {
		log.Fatal(err)
		return
	}
	//<Connector port="8088" protocol="HTTP/1.1"
	//               connectionTimeout="20000"
	//               redirectPort="443" />
	//
	var serverOkbaseXml = okbaseServer{
		XMLName:               serverXml.XMLName,
		Port:                  serverXml.Port,
		Shutdown:              serverXml.Shutdown,
		Listeners:             serverXml.Listeners,
		GlobalNamingResources: serverXml.GlobalNamingResources,
		Service: service{
			XMLName: serverXml.Service.XMLName,
			Name:    serverXml.Service.Name,
			Connector: connector{
				XMLName:           serverXml.Service.Connector.XMLName,
				Port:              "8080",
				Protocol:          "HTTP/1.1",
				ConnectionTimeout: "20000",
				RedirectPort:      "443",
				MaxParameterCount: serverXml.Service.Connector.MaxParameterCount,
			},
			Engine: engine{
				XMLName:     serverXml.Service.Engine.XMLName,
				Name:        serverXml.Service.Engine.Name,
				DefaultHost: serverXml.Service.Engine.DefaultHost,
				Realm:       serverXml.Service.Engine.Realm,
				//      <Host name=""  appBase=""
				//            unpackWARs="" autoDeploy="false">
				Host: host{
					XMLName:    serverXml.Service.Engine.Host.XMLName,
					Name:       "localhost",
					AppBase:    "webapps",
					UnpackWARs: true,
					AutoDeploy: false,
					Valve:      serverXml.Service.Engine.Host.Valve,
				},
			},
		},
	}

	fmt.Println("Successfully Unmarshaled server.xml")
	var xmlWriteFile *os.File = nil
	xmlWriteFile, err = os.Create(fileOutputPath)
	if err != nil {
		log.Fatal(err)
		return
	}
	if _, err = xmlWriteFile.WriteString(xml.Header); err != nil {
		log.Fatal(err)
		return
	}
	var xmlWriteBytes []byte = nil
	xmlWriteBytes, err = xml.MarshalIndent(&serverOkbaseXml, "", "  ")

	fmt.Println("Successfully Marshaled output server.xml")
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

	fmt.Println("Successfully Formated output server.xml")
	if _, err = xmlWriteFile.WriteString(xmlString); err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println("Successfully Written output server.xml")
	if err = xmlWriteFile.Close(); err != nil {
		log.Fatal(err)
		return
	}
}
