package saml

import (
	"log"

	"github.com/RobotsAndPencils/go-saml/util"
)

// ServiceProviderSettings provides settings to configure server acting as a SAML Service Provider.
// Expect only one IDP per SP in this configuration. If you need to configure multipe IDPs for an SP
// then configure multiple instances of this module
type ServiceProviderSettings struct {
	PublicCertPath              string
	PrivateKeyPath              string
	IDPSSOURL                   string
	IDPSSODescriptorURL         string
	IDPPublicCertPath           string
	AssertionConsumerServiceURL string
	SPSignRequest               bool

	hasInit       bool
	publicCert    string
	privateKey    string
	iDPPublicCert string
}

type IdentityProviderSettings struct {
}

func (s *ServiceProviderSettings) setHasInit() {
}

func (s *ServiceProviderSettings) Init() (err error) {
	if s.hasInit {
		log.Println("already initialized")
		log.Println("already init: ", s.PublicCert())
		return nil
	}
	log.Println("initializing ServiceProviderSettings")
	if s.SPSignRequest {
		s.publicCert, err = util.LoadCertificate(s.PublicCertPath)
		if err != nil {
			log.Println("error loading public certificate: ", err)
			s.hasInit = false
			panic(err)
		}

		s.privateKey, err = util.LoadCertificate(s.PrivateKeyPath)
		if err != nil {
			log.Println("error loading private certificate: ", err)
			s.hasInit = false
			panic(err)
		}
	}

	s.iDPPublicCert, err = util.LoadCertificate(s.IDPPublicCertPath)
	if err != nil {
		log.Println("error loading idp public certificate: ", err)
		s.hasInit = false
		panic(err)
	} else {
		if s.iDPPublicCert != "" {
			s.hasInit = true
		} else {
			log.Println("idp public cert empty")
		}
	}
	log.Println("first init idp pub cert: ", s.IDPPublicCert())
	return nil
}

func (s *ServiceProviderSettings) PublicCert() string {
	if !s.hasInit {
		panic("Must call ServiceProviderSettings.Init() first")
	}
	return s.publicCert
}

func (s *ServiceProviderSettings) PrivateKey() string {
	if !s.hasInit {
		panic("Must call ServiceProviderSettings.Init() first")
	}
	return s.privateKey
}

func (s *ServiceProviderSettings) IDPPublicCert() string {
	if !s.hasInit {
		panic("Must call ServiceProviderSettings.Init() first")
	}
	return s.iDPPublicCert
}
