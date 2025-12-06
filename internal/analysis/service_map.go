package analysis

import "strconv"

var commonPorts = map[int]string{
	20:  "FTP-DATA",
	21:  "FTP",
	22:  "SSH",
	23:  "Telnet",
	25:  "SMTP",
	53:  "DNS",
	80:  "HTTP",
	110: "POP3",
	143: "IMAP",
	443: "HTTPS",
	3306: "MySQL",
	5432: "PostgreSQL",
	6379: "Redis",
	8080: "HTTP-Alt",
}

// GetServiceName returns the common name for a port, or the port number as a string.
func GetServiceName(port int) string {
	if name, ok := commonPorts[port]; ok {
		return name
	}
	return strconv.Itoa(port)
}



