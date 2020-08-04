package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"time"

	"github.com/RobotsAndPencils/go-saml/util"
)

func ParseCompressedEncodedResponse(b64ResponseXML string) (*Response, error) {
	authnResponse := Response{}
	compressedXML, err := base64.StdEncoding.DecodeString(b64ResponseXML)
	if err != nil {
		return nil, err
	}
	bXML := util.Decompress(compressedXML)
	err = xml.Unmarshal(bXML, &authnResponse)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	authnResponse.originalString = string(bXML)
	return &authnResponse, nil

}

func ParseEncodedResponse(b64ResponseXML string) (*Response, error) {
	response := Response{}
	bytesXML, err := base64.StdEncoding.DecodeString(b64ResponseXML)
	if err != nil {
		return nil, err
	}

	err = xml.Unmarshal(bytesXML, &response)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	response.originalString = string(bytesXML)
	// fmt.Println(response.originalString)
	return &response, nil
}

func (r *Response) isResponseSigned(s *ServiceProviderSettings) bool {
	if len(r.Signature.SignatureValue.Value) == 0 && len(r.Assertion.Signature.SignatureValue.Value) == 0 {
		return false
	}
	return true
}

func (r *Response) isAssertionSigned(s *ServiceProviderSettings) bool {
	assertion, err := r.getAssertion()
	if err != nil {
		return false
	}
	if len(assertion.Signature.SignatureValue.Value) == 0 && len(assertion.Signature.SignatureValue.Value) == 0 {
		return false
	}
	return true
}

func (r *Response) Validate(s *ServiceProviderSettings) error {

	if r.Version != "2.0" {
		return errors.New("unsupported SAML Version")
	}

	if len(r.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}
	if r.isResponseSigned(s) {
		err := VerifyResponseSignature(r.originalString, s.IDPPublicCertPath)
		if err != nil {
			return err
		}
	}

	err := r.Decrypt(s.PrivateKeyPath)
	if err != nil {
		return err
	}
	xmlString := r.originalString
	if r.IsEncrypted() == true && r.decryptedString != "" {
		xmlString = r.decryptedString
	}

	// if it is encrypted, we need to verify the assertion signature (if present)
	if r.isAssertionSigned(s) {
		err = VerifyAssertionSignature(xmlString, s.IDPPublicCertPath)
		if err != nil {
			return err
		}
	}

	assertion, err := r.getAssertion()

	if err != nil {
		return err
	}

	if len(assertion.ID) == 0 {
		return errors.New("no Assertions")
	}
	if assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("assertion method exception")
	}

	if assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != s.AssertionConsumerServiceURL {
		return errors.New("subject recipient mismatch, expected: " + s.AssertionConsumerServiceURL + " not " + assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
	}

	//some saml providers do not send destination.
	if r.Destination != "" {
		if r.Destination != s.AssertionConsumerServiceURL && r.Destination != s.IDPSSODescriptorURL {
			return errors.New("destination mismatch expected: " + s.AssertionConsumerServiceURL + " or " + s.IDPSSODescriptorURL + " not " + r.Destination)
		}
	}
	if assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("assertion method exception")
	}

	if assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != s.AssertionConsumerServiceURL && assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != s.IDPSSODescriptorURL {
		return errors.New("subject recipient mismatch, expected: " + s.AssertionConsumerServiceURL + " not " + r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
	}

	//CHECK TIMES
	expires := assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
	notOnOrAfter, e := time.Parse(time.RFC3339, expires)
	if e != nil {
		return e
	}
	if notOnOrAfter.Before(time.Now()) {
		return errors.New("assertion has expired on: " + expires)
	}

	return nil
}
func (r *Response) IsEncrypted() bool {
	if r.EncryptedAssertion.EncryptedData.EncryptionMethod.Algorithm == "" {
		return false
	} else {
		return true
	}
}

func (r *Response) Decrypt(privateKeyPath string) error {
	s := r.originalString

	if r.IsEncrypted() == false {
		return nil
	}
	plainXML, err := DecryptResponse(s, privateKeyPath)
	if err != nil {
		return err
	}
	err = xml.Unmarshal([]byte(plainXML), &r)
	if err != nil {
		return err
	}

	r.decryptedString = plainXML
	return nil
}

func (r *Response) ValidateResponseSignature(s *ServiceProviderSettings) error {

	assertion, err := r.getAssertion()
	if err != nil {
		return err
	}

	if len(assertion.Signature.SignatureValue.Value) == 0 {
		return errors.New("no signature")
	}

	err = VerifyResponseSignature(r.originalString, s.IDPPublicCertPath)
	if err != nil {
		return err
	}

	return nil
}

func (r *Response) getAssertion() (Assertion, error) {

	assertion := Assertion{}

	if r.IsEncrypted() {
		assertion = r.EncryptedAssertion.Assertion
	} else {
		assertion = r.Assertion
	}

	if len(assertion.ID) == 0 {
		return assertion, errors.New("no Assertions")
	}
	return assertion, nil
}

func NewSignedResponse() *Response {
	return &Response{
		XMLName: xml.Name{
			Local: "samlp:Response",
		},
		SAMLP:        "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
		SAMLSIG:      "http://www.w3.org/2000/09/xmldsig#",
		ID:           util.ID(),
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format(RFC3339Micro),
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
		},
		Signature: Signature{
			XMLName: xml.Name{
				Local: "samlsig:Signature",
			},
			Id: util.ID(),
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "samlsig:SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "samlsig:CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "samlsig:SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "samlsig:Reference",
					},
					URI: "", // caller must populate "#" + ar.Id,
					Transforms: Transforms{
						XMLName: xml.Name{
							Local: "samlsig:Transforms",
						},
						Transform: []Transform{Transform{
							XMLName: xml.Name{
								Local: "samlsig:Transform",
							},
							Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
						}},
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "samlsig:DigestMethod",
						},
						Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "samlsig:DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "samlsig:SignatureValue",
				},
			},
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "samlsig:KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "samlsig:X509Data",
					},
					X509Certificate: X509Certificate{
						XMLName: xml.Name{
							Local: "samlsig:X509Certificate",
						},
						Cert: "", // caller must populate cert,
					},
				},
			},
		},
		Status: Status{
			XMLName: xml.Name{
				Local: "samlp:Status",
			},
			StatusCode: StatusCode{
				XMLName: xml.Name{
					Local: "samlp:StatusCode",
				},
				// TODO unsuccesful responses??
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
		Assertion: Assertion{
			XMLName: xml.Name{
				Local: "saml:Assertion",
			},
			XS:           "http://www.w3.org/2001/XMLSchema",
			XSI:          "http://www.w3.org/2001/XMLSchema-instance",
			SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
			Version:      "2.0",
			ID:           util.ID(),
			IssueInstant: time.Now().UTC().Format(RFC3339Micro),
			Issuer: Issuer{
				XMLName: xml.Name{
					Local: "saml:Issuer",
				},
				Url: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
			},
			Subject: Subject{
				XMLName: xml.Name{
					Local: "saml:Subject",
				},
				NameID: NameID{
					XMLName: xml.Name{
						Local: "saml:NameID",
					},
					Format:          "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
					Value:           "",
					SPNameQualifier: "",
				},
				SubjectConfirmation: SubjectConfirmation{
					XMLName: xml.Name{
						Local: "saml:SubjectConfirmation",
					},
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: SubjectConfirmationData{
						XMLName: xml.Name{
							Local: "saml:SubjectConfirmationData",
						},
						InResponseTo: "",
						NotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(RFC3339Micro),
						Recipient:    "",
					},
				},
			},
			Conditions: Conditions{
				XMLName: xml.Name{
					Local: "saml:Conditions",
				},
				NotBefore:            time.Now().Add(time.Minute * -5).UTC().Format(RFC3339Micro),
				NotOnOrAfter:         time.Now().Add(time.Minute * 5).UTC().Format(RFC3339Micro),
				AudienceRestrictions: []AudienceRestriction{},
			},
			AttributeStatement: AttributeStatement{
				XMLName: xml.Name{
					Local: "saml:AttributeStatement",
				},
				Attributes: []Attribute{},
			},
		},
	}
}

// AddAttribute add strong attribute to the Response
func (r *Response) AddAttribute(name, value string) {
	r.Assertion.AttributeStatement.Attributes = append(r.Assertion.AttributeStatement.Attributes, Attribute{
		XMLName: xml.Name{
			Local: "saml:Attribute",
		},
		Name:       name,
		NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		AttributeValues: []AttributeValue{
			{
				XMLName: xml.Name{
					Local: "saml:AttributeValue",
				},
				Type:  "xs:string",
				Value: value,
			},
		},
	})
}

func (r *Response) AddAudienceRestriction(value string) {
	r.Assertion.Conditions.AudienceRestrictions = append(r.Assertion.Conditions.AudienceRestrictions,
		AudienceRestriction{XMLName: xml.Name{
			Local: "saml:AudienceRestriction",
		},
			Audiences: []Audience{Audience{XMLName: xml.Name{
				Local: "saml:Audience",
			},
				Value: value,
			},
			},
		})
}

func (r *Response) AddAuthnStatement(transport string, sessionIndex string) {
	r.Assertion.AuthnStatements = append(r.Assertion.AuthnStatements, AuthnStatement{
		XMLName: xml.Name{
			Local: "saml:AuthnStatement",
		},
		AuthnInstant:        r.IssueInstant,
		SessionIndex:        sessionIndex,
		SessionNotOnOrAfter: r.Assertion.Conditions.NotOnOrAfter,
		AuthnContext: AuthnContext{
			XMLName: xml.Name{
				Local: "saml:AuthnContext",
			},
			AuthnContextClassRef: AuthnContextClassRef{
				XMLName: xml.Name{
					Local: "saml:AuthnContextClassRef",
				},
				Transport: transport,
			},
		},
	})
}

func (r *Response) String() (string, error) {
	b, err := xml.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (r *Response) SignedString(privateKeyPath string) (string, error) {
	s, err := r.String()
	if err != nil {
		return "", err
	}

	return SignResponse(s, privateKeyPath)
}

func (r *Response) EncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := r.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(signed))
	return b64XML, nil
}

func (r *Response) CompressedEncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := r.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(signed))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}

// GetAttribute by Name or by FriendlyName. Return blank string if not found
func (r *Response) GetAttribute(name string) string {
	attrStatement := AttributeStatement{}

	if r.IsEncrypted() {
		attrStatement = r.EncryptedAssertion.Assertion.AttributeStatement
	} else {
		attrStatement = r.Assertion.AttributeStatement
	}

	for _, attr := range attrStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			return attr.AttributeValues[0].Value
		}
	}
	return ""
}

func (r *Response) GetAttributeValues(name string) []string {
	var values []string
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			for _, v := range attr.AttributeValues {
				values = append(values, v.Value)
			}
		}
	}
	return values
}
