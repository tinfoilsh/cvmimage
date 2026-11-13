package timeanchor

import (
	"crypto/sha256"
	"encoding/asn1"
	"testing"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"time"
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
	binding := func(digest []byte) pkcs7.Attribute {
		value, err := asn1.Marshal(struct{ Certs []struct{ Hash []byte } }{
			Certs: []struct{ Hash []byte }{{digest}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return pkcs7.Attribute{Type: bindingOID, Value: asn1.RawValue{FullBytes: value}}
	}
	hash := sha256.Sum256(a.signer.Raw)
	validBinding := binding(hash[:])
	wrongBinding := binding(make([]byte, sha256.Size))
	for _, tc := range []struct {
		name        string
		attributes  []pkcs7.Attribute
		contentType asn1.ObjectIdentifier
		valid       bool
	}{
		{name: "valid", attributes: []pkcs7.Attribute{validBinding}, contentType: tstInfoOID, valid: true},
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
