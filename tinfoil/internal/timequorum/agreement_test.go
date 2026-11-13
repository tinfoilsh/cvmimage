package timequorum

import (
	"testing"
	"time"

	"github.com/beevik/ntp"
)

func TestAgreementRequiresThreeOperators(t *testing.T) {
	now := time.Now()
	operators := []Operator{Canonical, Cloudflare, Netnod, PTB, SIDN}
	for lost := 0; lost < 1<<len(operators); lost++ {
		var samples []Sample
		for i, operator := range operators {
			if lost&(1<<i) == 0 {
				samples = append(samples, Sample{operator, now.UTC(), now, time.Millisecond, ntp.LeapNoWarning})
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
	base := []Sample{{Canonical, now.UTC(), now, time.Millisecond, ntp.LeapNoWarning}, {Cloudflare, now.UTC(), now, time.Millisecond, ntp.LeapNoWarning}}
	for _, test := range []struct {
		name  string
		third Sample
	}{
		{"duplicate operator", base[0]},
		{"unknown operator", Sample{"unknown", now.UTC(), now, time.Millisecond, ntp.LeapNoWarning}},
		{"stale", Sample{Netnod, now.UTC(), now.Add(-MaxSampleAge - time.Nanosecond), time.Millisecond, ntp.LeapNoWarning}},
		{"future sample", Sample{Netnod, now.UTC(), now.Add(time.Nanosecond), time.Millisecond, ntp.LeapNoWarning}},
		{"unbounded", Sample{Netnod, now.UTC(), now, MaxSampleRadius + time.Nanosecond, ntp.LeapNoWarning}},
		{"negative radius", Sample{Netnod, now.UTC(), now, -time.Nanosecond, ntp.LeapNoWarning}},
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
		{Canonical, now.UTC(), now, 200 * time.Millisecond, ntp.LeapNoWarning},
		{Cloudflare, now.UTC().Add(-100 * time.Millisecond), now, 2 * time.Millisecond, ntp.LeapNoWarning},
		{Netnod, now.UTC().Add(100 * time.Millisecond), now, 2 * time.Millisecond, ntp.LeapNoWarning},
	}
	if agreement, err := Agree(samples, now); err == nil {
		t.Fatalf("disjoint intervals admitted: %+v", agreement)
	}
}

func TestAgreementRejectsOutliersAndPrefersFullOverlap(t *testing.T) {
	now := time.Now()
	good := []Sample{{Canonical, now.UTC(), now, 10 * time.Millisecond, ntp.LeapNoWarning}, {Cloudflare, now.UTC(), now, 20 * time.Millisecond, ntp.LeapNoWarning}, {Netnod, now.UTC(), now, 30 * time.Millisecond, ntp.LeapNoWarning}}
	bad := []Sample{{PTB, now.UTC().Add(time.Second), now, time.Millisecond, ntp.LeapNoWarning}, {SIDN, now.UTC().Add(-time.Second), now, time.Millisecond, ntp.LeapNoWarning}}
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
		{Canonical, now.UTC().Add(-age), now.Add(-age), time.Millisecond, ntp.LeapNoWarning},
		{Canonical, now.UTC().Add(time.Hour), now.Add(-age - time.Second), time.Millisecond, ntp.LeapNoWarning},
		{Cloudflare, now.UTC(), now, time.Millisecond, ntp.LeapNoWarning},
		{Netnod, now.UTC(), now, time.Millisecond, ntp.LeapNoWarning},
	}
	agreement, err := Agree(samples, now)
	if err != nil || len(agreement.Operators) != RequiredOperators || !agreement.UTC.Equal(now.UTC()) {
		t.Fatalf("agreement=%+v error=%v", agreement, err)
	}
}

func TestAgreementRequiresMatchingLeapIndications(t *testing.T) {
	now := time.Now()
	var samples []Sample
	for _, operator := range []Operator{Canonical, Cloudflare, Netnod, PTB, SIDN} {
		samples = append(samples, Sample{Operator: operator, UTC: now.UTC(), Received: now, Radius: time.Millisecond, Leap: ntp.LeapAddSecond})
	}
	samples[0].Leap = ntp.LeapNoWarning
	samples[1].Leap = ntp.LeapNoWarning
	agreement, err := Agree(samples, now)
	if err != nil || agreement.Leap != ntp.LeapAddSecond || len(agreement.Operators) != RequiredOperators {
		t.Fatalf("agreement=%+v error=%v", agreement, err)
	}
	samples[2].Leap = ntp.LeapDelSecond
	if agreement, err := Agree(samples, now); err == nil {
		t.Fatalf("conflicting leap indications admitted: %+v", agreement)
	}
}
