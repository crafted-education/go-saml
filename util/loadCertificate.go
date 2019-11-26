package util

import (
	"io/ioutil"
	"log"
	"regexp"
	"strings"
)

// LoadCertificate from file system
func LoadCertificate(certPath string) (string, error) {
	b, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Println("err in LoadCertificate: ", err)
		return "", err
	}
	cert := string(b)

	re := regexp.MustCompile("---(.*)CERTIFICATE(.*)---")
	cert = re.ReplaceAllString(cert, "")
	cert = strings.Trim(cert, " \n")
	cert = strings.Replace(cert, "\n", "", -1)
	if cert == "" {
		log.Println("cert is empty: ", err)
	}
	return cert, nil
}
