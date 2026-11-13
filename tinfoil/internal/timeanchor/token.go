package timeanchor

import (
	"bytes"
	"crypto"
	_ "crypto/sha1" // ESSCertID uses SHA-1 to identify a certificate, not to sign data.
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/digitorus/pkcs7"
)

const directoryNameTag = 4

var (
	tstInfoOID              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	signingCertificateOID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	signingCertificateV2OID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

func checkToken(token []byte, signed *pkcs7.PKCS7) error {
	content, err := sequence(token)
	if err != nil || len(content) != 2 || content[1].Class != asn1.ClassContextSpecific || content[1].Tag != 0 {
		return fmt.Errorf("invalid timestamp ContentInfo")
	}
	data, err := sequence(content[1].Bytes)
	if err != nil || len(data) < 4 {
		return fmt.Errorf("invalid timestamp SignedData")
	}
	encap, err := sequence(data[2].FullBytes)
	var contentType asn1.ObjectIdentifier
	if err != nil || len(encap) != 2 || decode(encap[0].FullBytes, &contentType) != nil || !contentType.Equal(tstInfoOID) {
		return fmt.Errorf("timestamp must encapsulate id-ct-TSTInfo")
	}
	if len(signed.Signers) != 1 {
		return fmt.Errorf("timestamp requires exactly one signer")
	}
	signer := signed.GetOnlySigner()
	info := signed.Signers[0]
	if signer == nil || !bytes.Equal(info.IssuerAndSerialNumber.IssuerName.FullBytes, signer.RawIssuer) ||
		info.IssuerAndSerialNumber.SerialNumber.Cmp(signer.SerialNumber) != 0 {
		return fmt.Errorf("timestamp signer certificate is unavailable")
	}
	seen := make(map[string]bool)
	for _, attribute := range info.AuthenticatedAttributes {
		id := attribute.Type
		if !id.Equal(signingCertificateOID) && !id.Equal(signingCertificateV2OID) &&
			!id.Equal(pkcs7.OIDAttributeContentType) && !id.Equal(pkcs7.OIDAttributeMessageDigest) {
			continue
		}
		if seen[id.String()] {
			return fmt.Errorf("duplicate timestamp signed attribute %s", id)
		}
		seen[id.String()] = true
		var value asn1.RawValue
		if err := decode(attribute.Value.Bytes, &value); err != nil {
			return fmt.Errorf("timestamp attribute %s requires one value: %w", id, err)
		}
		if id.Equal(pkcs7.OIDAttributeContentType) {
			if decode(value.FullBytes, &contentType) != nil || !contentType.Equal(tstInfoOID) {
				return fmt.Errorf("timestamp signed content-type must be id-ct-TSTInfo")
			}
		} else if id.Equal(signingCertificateOID) || id.Equal(signingCertificateV2OID) {
			if err := checkCertificate(value.FullBytes, signer, id.Equal(signingCertificateV2OID)); err != nil {
				return err
			}
		}
	}
	if !seen[pkcs7.OIDAttributeContentType.String()] || !seen[pkcs7.OIDAttributeMessageDigest.String()] ||
		(!seen[signingCertificateOID.String()] && !seen[signingCertificateV2OID.String()]) {
		return fmt.Errorf("timestamp lacks required signed attributes")
	}
	return nil
}

func checkCertificate(raw []byte, signer *x509.Certificate, v2 bool) error {
	value, err := sequence(raw)
	if err != nil || len(value) < 1 || len(value) > 2 {
		return fmt.Errorf("invalid timestamp signing-certificate attribute")
	}
	certs, err := sequence(value[0].FullBytes)
	if err != nil || len(certs) == 0 {
		return fmt.Errorf("timestamp signing-certificate attribute has no certificates")
	}
	first, err := sequence(certs[0].FullBytes)
	if err != nil || len(first) == 0 {
		return fmt.Errorf("invalid timestamp certificate identifier")
	}
	hash := crypto.SHA1
	if v2 {
		hash = crypto.SHA256
		if first[0].Tag == asn1.TagSequence {
			var algorithm pkix.AlgorithmIdentifier
			if err := decode(first[0].FullBytes, &algorithm); err != nil ||
				(len(algorithm.Parameters.FullBytes) != 0 && !bytes.Equal(algorithm.Parameters.FullBytes, asn1.NullBytes)) {
				return fmt.Errorf("invalid timestamp certificate hash algorithm")
			}
			switch {
			case algorithm.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA1):
				hash = crypto.SHA1
			case algorithm.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA256):
				hash = crypto.SHA256
			case algorithm.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA384):
				hash = crypto.SHA384
			case algorithm.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA512):
				hash = crypto.SHA512
			default:
				return fmt.Errorf("unsupported timestamp certificate hash algorithm")
			}
			first = first[1:]
		}
	}
	var digest []byte
	if len(first) < 1 || len(first) > 2 || decode(first[0].FullBytes, &digest) != nil {
		return fmt.Errorf("invalid timestamp certificate hash")
	}
	h := hash.New()
	h.Write(signer.Raw)
	if !bytes.Equal(digest, h.Sum(nil)) {
		return fmt.Errorf("timestamp certificate hash does not match signer")
	}
	if len(first) == 2 {
		var issuerSerial struct {
			Issuer []asn1.RawValue
			Serial *big.Int
		}
		if decode(first[1].FullBytes, &issuerSerial) != nil || issuerSerial.Serial.Cmp(signer.SerialNumber) != 0 {
			return fmt.Errorf("timestamp certificate serial does not match signer")
		}
		for _, name := range issuerSerial.Issuer {
			if name.Class == asn1.ClassContextSpecific && name.Tag == directoryNameTag && bytes.Equal(name.Bytes, signer.RawIssuer) {
				return nil
			}
		}
		return fmt.Errorf("timestamp certificate issuer does not match signer")
	}
	return nil
}

func decode(raw []byte, value any) error {
	rest, err := asn1.Unmarshal(raw, value)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing ASN.1 data")
	}
	return nil
}

func sequence(raw []byte) ([]asn1.RawValue, error) {
	var fields []asn1.RawValue
	if err := decode(raw, &fields); err != nil {
		return nil, err
	}
	return fields, nil
}
