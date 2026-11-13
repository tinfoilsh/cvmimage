package timequorum

import (
	"testing"
	"time"
)

func TestAgreementRequiresThreeOperators(t *testing.T) {
	now := time.Now()
	operators := []Operator{Canonical, Cloudflare, Netnod, PTB, SIDN}
	for lost := 0; lost < 1<<len(operators); lost++ {
		var samples []Sample
		for i, operator := range operators {
			if lost&(1<<i) == 0 {
				samples = append(samples, Sample{operator, now.UTC(), now, time.Millisecond})
			}
		}
		agreement, err := Agree(samples, now)
		if (err == nil) != (len(samples) >= RequiredOperators) {
			t.Fatalf("outage mask=%d agreement=%+v error=%v", lost, agreement, err)
		}
		if err == nil && (!agreement.UTC.Equal(now.UTC()) || len(agreement.Operators) != len(samples)) {
			t.Fatalf("incorrect agreement: %+v", agreement)
		}
	}
}

func TestAgreementFiltersUnusableSamples(t *testing.T) {
	now := time.Now()
	base := []Sample{{Canonical, now.UTC(), now, time.Millisecond}, {Cloudflare, now.UTC(), now, time.Millisecond}}
	for _, test := range []struct {
		name  string
		third Sample
	}{
		{"duplicate operator", base[0]},
		{"unknown operator", Sample{"unknown", now.UTC(), now, time.Millisecond}},
		{"stale", Sample{Netnod, now.UTC(), now.Add(-MaxSampleAge - time.Nanosecond), time.Millisecond}},
		{"future sample", Sample{Netnod, now.UTC(), now.Add(time.Nanosecond), time.Millisecond}},
		{"unbounded", Sample{Netnod, now.UTC(), now, MaxSampleRadius + time.Nanosecond}},
		{"negative radius", Sample{Netnod, now.UTC(), now, -time.Nanosecond}},
		{"zero timestamp", Sample{Operator: Netnod, Received: now}},
		{"zero receipt", Sample{Operator: Netnod, UTC: now.UTC()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if agreement, err := Agree(append(base, test.third), now); err == nil {
				t.Fatalf("unusable sample admitted: %+v", agreement)
			}
		})
	}
}

func TestPairwiseOverlapDoesNotEstablishAgreement(t *testing.T) {
	now := time.Now()
	samples := []Sample{
		{Canonical, now.UTC(), now, 200 * time.Millisecond},
		{Cloudflare, now.UTC().Add(-100 * time.Millisecond), now, 2 * time.Millisecond},
		{Netnod, now.UTC().Add(100 * time.Millisecond), now, 2 * time.Millisecond},
	}
	if agreement, err := Agree(samples, now); err == nil {
		t.Fatalf("disjoint intervals admitted: %+v", agreement)
	}
}

func TestAgreementRejectsOutliersAndPrefersFullOverlap(t *testing.T) {
	now := time.Now()
	good := []Sample{{Canonical, now.UTC(), now, 10 * time.Millisecond}, {Cloudflare, now.UTC(), now, 20 * time.Millisecond}, {Netnod, now.UTC(), now, 30 * time.Millisecond}}
	bad := []Sample{{PTB, now.UTC().Add(time.Second), now, time.Millisecond}, {SIDN, now.UTC().Add(-time.Second), now, time.Millisecond}}
	agreement, err := Agree(append(good, bad...), now)
	if err != nil || len(agreement.Operators) != RequiredOperators || !agreement.UTC.Equal(now.UTC()) {
		t.Fatalf("agreement=%+v error=%v", agreement, err)
	}
	for i := range bad {
		bad[i].UTC = now.UTC()
	}
	agreement, err = Agree(append(good, bad...), now)
	if err != nil || len(agreement.Operators) != len(good)+len(bad) {
		t.Fatalf("full overlap not selected: %+v error=%v", agreement, err)
	}
}

func TestAgreementProjectsFromReceiptAndCountsProviderOnce(t *testing.T) {
	now := time.Now()
	const age = time.Second
	samples := []Sample{
		{Canonical, now.UTC().Add(-age), now.Add(-age), time.Millisecond},
		{Canonical, now.UTC().Add(time.Hour), now.Add(-age - time.Second), time.Millisecond},
		{Cloudflare, now.UTC(), now, time.Millisecond},
		{Netnod, now.UTC(), now, time.Millisecond},
	}
	agreement, err := Agree(samples, now)
	if err != nil || len(agreement.Operators) != RequiredOperators || !agreement.UTC.Equal(now.UTC()) {
		t.Fatalf("agreement=%+v error=%v", agreement, err)
	}
}
