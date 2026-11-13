package timeanchor

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

func TestVerifyRequiresSignedCertificateBinding(t *testing.T) {
	a := newTestAuthority(t, "test")
	q, err := newQuery()
	if err != nil {
		t.Fatal(err)
	}
	asked, err := timestamp.ParseRequest(q.encoded)
	if err != nil {
		t.Fatal(err)
	}
	original, err := timestamp.ParseResponse(a.sign(t, asked, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := pkcs7.Parse(original.RawToken)
	if err != nil {
		t.Fatal(err)
	}
	tstInfoOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	bindingOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	binding := func(digest []byte, issuers [][]byte, serial *big.Int) pkcs7.Attribute {
		var issuerSerial asn1.RawValue
		if serial != nil {
			var names []asn1.RawValue
			for _, issuer := range issuers {
				names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: directoryNameTag, IsCompound: true, Bytes: issuer})
			}
			encoded, err := asn1.Marshal(struct {
				Issuer []asn1.RawValue
				Serial *big.Int
			}{names, serial})
			if err != nil {
				t.Fatal(err)
			}
			issuerSerial.FullBytes = encoded
		}
		type certID struct {
			Hash         []byte
			IssuerSerial asn1.RawValue `asn1:"optional"`
		}
		value, err := asn1.Marshal(struct{ Certs []certID }{[]certID{{digest, issuerSerial}}})
		if err != nil {
			t.Fatal(err)
		}
		return pkcs7.Attribute{Type: bindingOID, Value: asn1.RawValue{FullBytes: value}}
	}
	hash := sha256.Sum256(a.signer.Raw)
	validBinding := binding(hash[:], nil, nil)
	wrongBinding := binding(make([]byte, sha256.Size), nil, nil)
	legacyHash := sha1.Sum(a.signer.Raw)
	legacyBinding := binding(legacyHash[:], nil, nil)
	legacyBinding.Type = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	wrongLegacyBinding := binding(make([]byte, sha1.Size), nil, nil)
	wrongLegacyBinding.Type = legacyBinding.Type

	type explicitCertID struct {
		Algorithm pkix.AlgorithmIdentifier
		Hash      []byte
	}
	sha1V2, err := asn1.Marshal(struct{ Certs []explicitCertID }{[]explicitCertID{{pkix.AlgorithmIdentifier{Algorithm: pkcs7.OIDDigestAlgorithmSHA1}, legacyHash[:]}}})
	if err != nil {
		t.Fatal(err)
	}
	sha1V2Binding := pkcs7.Attribute{Type: bindingOID, Value: asn1.RawValue{FullBytes: sha1V2}}
	for _, tc := range []struct {
		name        string
		attributes  []pkcs7.Attribute
		contentType asn1.ObjectIdentifier
		valid       bool
	}{
		{name: "valid", attributes: []pkcs7.Attribute{validBinding}, contentType: tstInfoOID, valid: true},
		{name: "valid issuer and serial", attributes: []pkcs7.Attribute{binding(hash[:], [][]byte{a.signer.RawIssuer}, a.signer.SerialNumber)}, contentType: tstInfoOID, valid: true},
		{name: "wrong issuer", attributes: []pkcs7.Attribute{binding(hash[:], [][]byte{a.signer.RawSubject}, a.signer.SerialNumber)}, contentType: tstInfoOID},
		{name: "wrong serial", attributes: []pkcs7.Attribute{binding(hash[:], [][]byte{a.signer.RawIssuer}, big.NewInt(3))}, contentType: tstInfoOID},
		{name: "extra issuer", attributes: []pkcs7.Attribute{binding(hash[:], [][]byte{a.signer.RawIssuer, a.signer.RawSubject}, a.signer.SerialNumber)}, contentType: tstInfoOID},
		{name: "SHA-1 in v2", attributes: []pkcs7.Attribute{sha1V2Binding}, contentType: tstInfoOID},
		{name: "valid legacy", attributes: []pkcs7.Attribute{legacyBinding}, contentType: tstInfoOID, valid: true},
		{name: "wrong legacy hash", attributes: []pkcs7.Attribute{wrongLegacyBinding}, contentType: tstInfoOID},
		{name: "both bindings", attributes: []pkcs7.Attribute{legacyBinding, validBinding}, contentType: tstInfoOID, valid: true},
		{name: "one binding wrong", attributes: []pkcs7.Attribute{wrongLegacyBinding, validBinding}, contentType: tstInfoOID},
		{name: "missing binding", contentType: tstInfoOID},
		{name: "wrong hash", attributes: []pkcs7.Attribute{wrongBinding}, contentType: tstInfoOID},
		{name: "duplicate binding", attributes: []pkcs7.Attribute{validBinding, wrongBinding}, contentType: tstInfoOID},
		{name: "wrong content type", attributes: []pkcs7.Attribute{validBinding}, contentType: pkcs7.OIDData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := pkcs7.NewSignedData(parsed.Content)
			if err != nil {
				t.Fatal(err)
			}
			data.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
			data.SetContentType(tc.contentType)
			data.GetSignedData().Version = 3
			if err := data.AddSigner(a.signer, a.key, pkcs7.SignerInfoConfig{
				ExtraSignedAttributes: tc.attributes,
			}); err != nil {
				t.Fatal(err)
			}
			token, err := data.Finish()
			if err != nil {
				t.Fatal(err)
			}
			response, err := asn1.Marshal(struct {
				Status struct{ Status int }
				Token  asn1.RawValue
			}{Token: asn1.RawValue{FullBytes: token}})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = q.verify(response, []Authority{a.Authority})
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil {
					t.Fatal("invalid timestamp verified")
				}
			}
		})
	}
}
