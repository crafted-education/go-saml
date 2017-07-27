//Copyright (c) 2015, Ross Kinder
//All rights reserved.
//
//Redistribution and use in source and binary forms, with or without modification,
//are permitted provided that the following conditions are met:
//
//1. Redistributions of source code must retain the above copyright notice, this
//list of conditions and the following disclaimer.
//
//2. Redistributions in binary form must reproduce the above copyright notice,
//this list of conditions and the following disclaimer in the documentation
//and/or other materials provided with the distribution.
//
//THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package saml

import (
	"encoding/xml"
	"time"
)

const DefaultValidDuration = time.Hour * 24 * 2

func (sp *ServiceProviderSettings) GetEntityDescriptor() (string, error) {

	validDuration := DefaultValidDuration
	//	if sp.MetadataValidDuration > 0 {
	//		validDuration = sp.MetadataValidDuration
	//	}

	authnRequestsSigned := false
	wantAssertionsSigned := true
	metadata := &EntityDescriptor{
		EntityID:   sp.MetadataURL,
		ValidUntil: TimeNow().Add(validDuration),

		SPSSODescriptors: []SPSSODescriptor{
			SPSSODescriptor{
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: KeyInfo{
									XMLName: xml.Name{
										Local: "ds:KeyInfo",
									},
									X509Data: X509Data{
										XMLName: xml.Name{
											Local: "ds:X509Data",
										},
										X509Certificate: X509Certificate{
											XMLName: xml.Name{
												Local: "ds:X509Certificate",
											},
											Cert: sp.PublicCert(),
										},
									},
								},
							},
							{
								Use: "encryption",
								KeyInfo: KeyInfo{
									XMLName: xml.Name{
										Local: "ds:KeyInfo",
									},
									X509Data: X509Data{
										XMLName: xml.Name{
											Local: "ds:X509Data",
										},
										X509Certificate: X509Certificate{
											XMLName: xml.Name{
												Local: "ds:X509Certificate",
											},
											Cert: sp.PublicCert(),
										},
									},
								},
								EncryptionMethods: []EncryptionMethod{
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
								},
							},
						},
					},
				},
				AuthnRequestsSigned:  &authnRequestsSigned,
				WantAssertionsSigned: &wantAssertionsSigned,

				AssertionConsumerServices: []IndexedEndpoint{
					IndexedEndpoint{
						Binding:  HTTPPostBinding,
						Location: sp.AssertionConsumerServiceURL,
						Index:    1,
					},
				},
			},
		},
	}
	buf, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", err
	}
	return string(buf), nil

	//	d := EntityDescriptor{
	//		XMLName: xml.Name{
	//			Local: "md:EntityDescriptor",
	//		},
	//		DS:       "http://www.w3.org/2000/09/xmldsig#",
	//		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
	//		MD:       "urn:oasis:names:tc:SAML:2.0:metadata",
	//		EntityId: s.AssertionConsumerServiceURL,
	//
	//		Extensions: Extensions{
	//			XMLName: xml.Name{
	//				Local: "md:Extensions",
	//			},
	//			Alg:    "urn:oasis:names:tc:SAML:metadata:algsupport",
	//			MDAttr: "urn:oasis:names:tc:SAML:metadata:attribute",
	//			MDRPI:  "urn:oasis:names:tc:SAML:metadata:rpi",
	//		},
	//		SPSSODescriptor: SPSSODescriptor{
	//			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
	//			SigningKeyDescriptor: KeyDescriptor{
	//				XMLName: xml.Name{
	//					Local: "md:KeyDescriptor",
	//				},
	//
	//				Use: "signing",
	//				KeyInfo: KeyInfo{
	//					XMLName: xml.Name{
	//						Local: "ds:KeyInfo",
	//					},
	//					X509Data: X509Data{
	//						XMLName: xml.Name{
	//							Local: "ds:X509Data",
	//						},
	//						X509Certificate: X509Certificate{
	//							XMLName: xml.Name{
	//								Local: "ds:X509Certificate",
	//							},
	//							Cert: s.PublicCert(),
	//						},
	//					},
	//				},
	//			},
	//			EncryptionKeyDescriptor: KeyDescriptor{
	//				XMLName: xml.Name{
	//					Local: "md:KeyDescriptor",
	//				},
	//
	//				Use: "encryption",
	//				KeyInfo: KeyInfo{
	//					XMLName: xml.Name{
	//						Local: "ds:KeyInfo",
	//					},
	//					X509Data: X509Data{
	//						XMLName: xml.Name{
	//							Local: "ds:X509Data",
	//						},
	//						X509Certificate: X509Certificate{
	//							XMLName: xml.Name{
	//								Local: "ds:X509Certificate",
	//							},
	//							Cert: s.PublicCert(),
	//						},
	//					},
	//				},
	//			},
	//			// SingleLogoutService{
	//			// 	XMLName: xml.Name{
	//			// 		Local: "md:SingleLogoutService",
	//			// 	},
	//			// 	Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
	//			// 	Location: "---TODO---",
	//			// },
	//			AssertionConsumerServices: []AssertionConsumerService{
	//				{
	//					XMLName: xml.Name{
	//						Local: "md:AssertionConsumerService",
	//					},
	//					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	//					Location: s.AssertionConsumerServiceURL,
	//					Index:    "0",
	//				},
	//				{
	//					XMLName: xml.Name{
	//						Local: "md:AssertionConsumerService",
	//					},
	//					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
	//					Location: s.AssertionConsumerServiceURL,
	//					Index:    "1",
	//				},
	//			},
	//		},
	//	}
	//	b, err := xml.MarshalIndent(d, "", "    ")
	//	if err != nil {
	//		return "", err
	//	}
	//
	//	newMetadata := fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b)
	//return string(newMetadata), nil
}
