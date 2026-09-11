package attestation

import (
	"fmt"
	"log"

	verifier "tinfoil/internal/legacy"
)

type CPU struct {
	RawReport []byte
	Platform  string
	V2Doc     *verifier.Document
}

func CollectCPU(aBody BodyV2, dummy bool) (*CPU, error) {
	log.Printf("Attestation body: tls_fp=%x hpke=%x", aBody.TLSKeyFP, aBody.HPKEKey)
	userData := aBody.Marshal()

	if dummy {
		log.Println("Using dummy attestation report")
		doc := DummyReport(userData)
		return &CPU{
			RawReport: userData[:],
			Platform:  PlatformDummy,
			V2Doc:     doc,
		}, nil
	}

	log.Println("Fetching hardware attestation report")
	rawReport, platform, err := Report(userData)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation report: %w", err)
	}

	v2Doc, err := V2Document(rawReport, platform)
	if err != nil {
		return nil, fmt.Errorf("building V2 document: %w", err)
	}

	return &CPU{
		RawReport: rawReport,
		Platform:  platform,
		V2Doc:     v2Doc,
	}, nil
}
