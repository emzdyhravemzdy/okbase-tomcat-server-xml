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
	proxySettings := false

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
	type Connector struct {
		XMLName  xml.Name `xml:"Connector"`
		Port     string   `xml:"port,attr"`
		Protocol string   `xml:"protocol,attr"`
	}
	type connectorHttp struct {
		Connector
		ConnectionTimeout string `xml:"connectionTimeout,attr"`
		RedirectPort      string `xml:"redirectPort,attr"`
		MaxParameterCount int    `xml:"maxParameterCount,attr"`
	}
	// <Connector port="8443" protocol="org.apache.coyote.http11.Http11AprProtocol"
	//               SSLEnabled="true" secure="true" scheme="https"
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
	//        <SSLHostConfig protocols="TLSv1.2,TLSv1.3"
	//       	ciphers="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256" >
	//            <Certificate certificateKeystoreFile="${catalina.home}/conf/certificate.pfx"
	//                         certificateKeystorePassword="tomcat"
	//                         certificateKeystoreType="PKCS12"
	//            />
	//     </SSLHostConfig>
	//  </Connector>
	type connectorSsl struct {
		Connector
		SSLEnabled              bool   `xml:"SSLEnabled,attr"`
		Secure                  bool   `xml:"secure,attr"`
		Scheme                  string `xml:"scheme,attr"`
		SSLProtocol             string `xml:"SSLProtocol,attr"`
		SSLCipherSuite          string `xml:"SSLCipherSuite,attr"`
		SSLHonorCipherOrder     bool   `xml:"SSLHonorCipherOrder,attr"`
		SSLDisableCompression   bool   `xml:"SSLDisableCompression,attr"`
		SSLCertificateFile      string `xml:"SSLCertificateFile,attr"`
		SSLCertificateKeyFile   string `xml:"SSLCertificateKeyFile,attr"`
		SSLCertificateChainFile string `xml:"SSLCertificateChainFile,attr"`
		SSLPassword             string `xml:"SSLPassword,attr"`
		DisableUploadTimeout    bool   `xml:"disableUploadTimeout,attr"`
		MaxThreads              int    `xml:"maxThreads,attr"`
		AcceptCount             int    `xml:"acceptCount,attr"`
		MaxHttpHeaderSize       int    `xml:"maxHttpHeaderSize,attr"`
	}
	type certificate struct {
		XMLName                     xml.Name `xml:"Certificate"`
		CertificateKeystoreFile     string   `xml:"certificateKeystoreFile,attr"`
		CertificateKeystorePassword string   `xml:"certificateKeystorePassword,attr"`
		CertificateKeystoreType     string   `xml:"certificateKeystoreType,attr"`
	}
	type sslHostConfig struct {
		XMLName     xml.Name    `xml:"SSLHostConfig"`
		Protocols   string      `xml:"protocols,attr"`
		Ciphers     string      `xml:"ciphers,attr"`
		Certificate certificate `xml:"Certificate"`
	}
	type upgradeProtocol struct {
		XMLName   xml.Name `xml:"UpgradeProtocol"`
		ClassName string   `xml:"className,attr"`
	}
	type connectorPfx struct {
		Connector
		MaxThreads      int             `xml:"maxThreads,attr"`
		SSLEnabled      bool            `xml:"SSLEnabled,attr"`
		UpgradeProtocol upgradeProtocol `xml:"UpgradeProtocol"`
		SSLHostConfig   sslHostConfig   `xml:"SSLHostConfig"`
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
	// <Valve className="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false" />
	//
	//<!--   TOHLE ODKOMENTOVAT POKUD TO BEZI ZA PROXY
	//<Valve
	//className="org.apache.catalina.valves.RemoteIpValve"
	//internalProxies="192\.168\.250\.64"
	//remoteIpHeader="x-forwarded-for"
	//proxiesHeader="x-forwarded-by"
	//protocolHeader="x-forwarded-proto"/>
	//
	//<Valve
	//className="org.apache.catalina.valves.AccessLogValve"
	//directory="logs"
	//prefix="localhost_access_log"
	//suffix=".txt"
	//pattern="%{org.apache.catalina.AccessLog.RemoteAddr}r %h %l %u %t &quot;%r&quot; %s %b"
	//resolveHosts="false"/>
	//-->
	//
	//<!--  TOHLE ZAKOMENTOVAT POKUD TO BEZI ZA PROXY  -->
	//<Valve
	//className="org.apache.catalina.valves.AccessLogValve"
	//directory="logs"
	//prefix="localhost_access_log"
	//suffix=".txt"
	//pattern="%h %l %u %t &quot;%r&quot; %s %b" />

	//<Valve className="org.apache.catalina.valves.AccessLogValve"
	//directory="logs"
	//prefix="localhost_access_log"
	//suffix=".txt"
	//pattern="%h %l %u %t &quot;%r&quot; %s %b" />
	type Valve struct {
		XMLName   xml.Name `xml:"Valve"`
		ClassName string   `xml:"className,attr"`
	}
	type valveNoProxy struct {
		Valve
		Directory string `xml:"directory,attr"`
		Prefix    string `xml:"prefix,attr"`
		Suffix    string `xml:"suffix,attr"`
		Pattern   string `xml:"pattern,attr"`
	}
	type valveProxy struct {
		Valve
		InternalProxies string `xml:"internalProxies,attr"`
		RemoteIpHeader  string `xml:"remoteIpHeader,attr"`
		ProxiesHeader   string `xml:"proxiesHeader,attr"`
		ProtocolHeader  string `xml:"protocolHeader,attr"`
	}
	//<Host name="localhost"  appBase="webapps" unpackWARs="true" autoDeploy="true">
	type host struct {
		XMLName    xml.Name     `xml:"Host"`
		Name       string       `xml:"name,attr"`
		AppBase    string       `xml:"appBase,attr"`
		UnpackWARs bool         `xml:"unpackWARs,attr"`
		AutoDeploy bool         `xml:"autoDeploy,attr"`
		Valve      valveNoProxy `xml:"Valve"`
	}
	type hostOkbase struct {
		XMLName    xml.Name `xml:"Host"`
		Name       string   `xml:"name,attr"`
		AppBase    string   `xml:"appBase,attr"`
		UnpackWARs bool     `xml:"unpackWARs,attr"`
		AutoDeploy bool     `xml:"autoDeploy,attr"`
		Valve      []any    `xml:"Valve"`
	}
	//<Engine name="Catalina" defaultHost="localhost">
	type engine struct {
		XMLName     xml.Name `xml:"Engine"`
		Name        string   `xml:"name,attr"`
		DefaultHost string   `xml:"defaultHost,attr"`
		Realm       realm    `xml:"Realm"`
		Host        host     `xml:"Host"`
	}
	type engineOkbbase struct {
		XMLName     xml.Name   `xml:"Engine"`
		Name        string     `xml:"name,attr"`
		DefaultHost string     `xml:"defaultHost,attr"`
		Realm       realm      `xml:"Realm"`
		Host        hostOkbase `xml:"Host"`
	}
	//<Service name="Catalina">
	type service struct {
		XMLName    xml.Name        `xml:"Service"`
		Name       string          `xml:"name,attr"`
		Connectors []connectorHttp `xml:"Connector"`
		Engine     engine          `xml:"Engine"`
	}
	type serviceOkbase struct {
		XMLName    xml.Name      `xml:"Service"`
		Name       string        `xml:"name,attr"`
		Connectors []any         `xml:"Connector"`
		Engine     engineOkbbase `xml:"Engine"`
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
		Service               serviceOkbase         `xml:"Service"`
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
	var connector1 connectorHttp
	if len(serverXml.Service.Connectors) > 0 {
		var x any = serverXml.Service.Connectors[0]
		switch t := x.(type) {
		case connectorHttp:
			connector1 = t
		case Connector:
			connector1.XMLName = t.XMLName
			connector1.Port = t.Port
			connector1.Protocol = t.Protocol
		}
	}
	connector1.Port = "8080"
	connector1.Protocol = "HTTP/1.1"
	connector1.ConnectionTimeout = "20000"
	connector1.RedirectPort = "443"

	var connectors []any = []any{
		connector1,
		connectorSsl{
			Connector: Connector{
				Port:     "8443",
				Protocol: "org.apache.coyote.http11.Http11AprProtocol",
			},
			SSLEnabled:              true,
			Secure:                  true,
			Scheme:                  "https",
			SSLProtocol:             "TLSv1.2+TLSv1.3",
			SSLCipherSuite:          "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
			SSLHonorCipherOrder:     true,
			SSLDisableCompression:   true,
			SSLCertificateFile:      "${catalina.home}/conf/certificate.crt",
			SSLCertificateKeyFile:   "${catalina.home}/conf/private.key",
			SSLCertificateChainFile: "${catalina.home}/conf/ca.crt",
			SSLPassword:             "",
			DisableUploadTimeout:    true,
			MaxThreads:              200,
			AcceptCount:             100,
			MaxHttpHeaderSize:       49152,
		},
		connectorPfx{
			Connector: Connector{
				Port:     "8443",
				Protocol: "org.apache.coyote.http11.Http11AprProtocol",
			},
			MaxThreads: 150,
			SSLEnabled: true,
			UpgradeProtocol: upgradeProtocol{
				ClassName: "org.apache.coyote.http2.Http2Protocol",
			},
			SSLHostConfig: sslHostConfig{
				Protocols: "TLSv1.2,TLSv1.3",
				Ciphers:   "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
				Certificate: certificate{
					CertificateKeystoreFile:     "${catalina.home}/conf/certificate.pfx",
					CertificateKeystorePassword: "tomcat",
					CertificateKeystoreType:     "PKCS12",
				},
			},
		},
	}
	var valves []any
	if proxySettings {
		valves = append(valves, valveNoProxy{
			Valve: Valve{
				XMLName:   serverXml.Service.Engine.Host.Valve.XMLName,
				ClassName: "org.apache.catalina.valves.AccessLogValve",
			},
			Directory: "logs",
			Prefix:    "localhost_access_log",
			Suffix:    ".txt",
			Pattern:   "%h %l %u %t &quot;%r&quot; %s %b",
		})
	} else {
		valves = append(valves, valveProxy{
			Valve: Valve{
				XMLName:   serverXml.Service.Engine.Host.Valve.XMLName,
				ClassName: "org.apache.catalina.valves.RemoteIpValve",
			},
			InternalProxies: "192.168.250.64",
			RemoteIpHeader:  "x-forwarded-for",
			ProxiesHeader:   "x-forwarded-by",
			ProtocolHeader:  "x-forwarded-proto",
		},
			valveNoProxy{
				Valve: Valve{
					XMLName:   serverXml.Service.Engine.Host.Valve.XMLName,
					ClassName: "org.apache.catalina.valves.AccessLogValve",
				},
				Directory:    "logs",
				Prefix:       "localhost_access_log",
				Suffix:       ".txt",
				Pattern:      "%{org.apache.catalina.AccessLog.RemoteAddr}r %h %l %u %t &quot;%r&quot; %s %b",
				ResolveHosts: false,
			})
	}
	fmt.Println("Successfully Unmarshalled server.xml")

	var serverOkbaseXml = okbaseServer{
		XMLName:               serverXml.XMLName,
		Port:                  serverXml.Port,
		Shutdown:              serverXml.Shutdown,
		Listeners:             serverXml.Listeners,
		GlobalNamingResources: serverXml.GlobalNamingResources,
		Service: serviceOkbase{
			XMLName:    serverXml.Service.XMLName,
			Name:       serverXml.Service.Name,
			Connectors: connectors,
			Engine: engineOkbbase{
				XMLName:     serverXml.Service.Engine.XMLName,
				Name:        serverXml.Service.Engine.Name,
				DefaultHost: serverXml.Service.Engine.DefaultHost,
				Realm:       serverXml.Service.Engine.Realm,
				Host: hostOkbase{
					XMLName:    serverXml.Service.Engine.Host.XMLName,
					Name:       "localhost",
					AppBase:    "webapps",
					UnpackWARs: true,
					AutoDeploy: false,
					Valve:      valves,
				},
			},
		},
	}

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
