package timequorum

import (
	"errors"
	"sort"
	"time"

	"github.com/beevik/ntp"

	"tinfoil/internal/ntsrelay"
)

const (
	RequiredOperators = 3
	MaxSampleRadius   = 250 * time.Millisecond
	MaxSampleAge      = ntsrelay.ExchangeLimit
)

type Operator string

const (
	Canonical  Operator = "canonical"
	Cloudflare Operator = "cloudflare"
	Netnod     Operator = "netnod"
	PTB        Operator = "ptb"
	SIDN       Operator = "sidn"
)

func (operator Operator) valid() bool {
	switch operator {
	case Canonical, Cloudflare, Netnod, PTB, SIDN:
		return true
	}
	return false
}

// Sample contains an authenticated upstream estimate at Received, which must
// retain its local monotonic reading. UTC is independent of the guest's date.
type Sample struct {
	Operator Operator
	UTC      time.Time
	Received time.Time
	Radius   time.Duration
	Leap     ntp.LeapIndicator
}

type Agreement struct {
	UTC       time.Time
	Observed  time.Time
	Operators []Operator
	Leap      ntp.LeapIndicator
	oldest    time.Time
}

type interval struct {
	operator     Operator
	lower, upper time.Time
	leap         ntp.LeapIndicator
	received     time.Time
}

// Agree counts operators, not addresses. A common intersection is necessary:
// overlapping pairs joined by a broad interval do not establish a quorum.
func Agree(samples []Sample, now time.Time) (Agreement, error) {
	fresh := make(map[Operator]Sample)
	for _, sample := range samples {
		age := now.Sub(sample.Received)
		if !sample.Operator.valid() || sample.UTC.IsZero() || sample.Received.IsZero() || age < 0 || age > MaxSampleAge || sample.Radius < 0 || sample.Radius > MaxSampleRadius || sample.Leap >= ntp.LeapNotInSync {
			continue
		}
		previous, exists := fresh[sample.Operator]
		if !exists || sample.Received.After(previous.Received) || sample.Received.Equal(previous.Received) && sample.Radius < previous.Radius {
			fresh[sample.Operator] = sample
		}
	}
	intervals := make([]interval, 0, len(fresh))
	for operator, sample := range fresh {
		center := sample.UTC.Add(now.Sub(sample.Received))
		intervals = append(intervals, interval{operator, center.Add(-sample.Radius), center.Add(sample.Radius), sample.Leap, sample.Received})
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].operator < intervals[j].operator })
	var best Agreement
	var bestWidth time.Duration
	for _, candidate := range intervals {
		point := candidate.lower
		lower, upper := point, candidate.upper
		oldest := candidate.received
		var operators []Operator
		for _, other := range intervals {
			if other.leap != candidate.leap || point.Before(other.lower) || point.After(other.upper) {
				continue
			}
			operators = append(operators, other.operator)
			if other.received.Before(oldest) {
				oldest = other.received
			}
			if other.lower.After(lower) {
				lower = other.lower
			}
			if other.upper.Before(upper) {
				upper = other.upper
			}
		}
		if len(operators) < RequiredOperators {
			continue
		}
		width := upper.Sub(lower)
		if len(operators) > len(best.Operators) || len(operators) == len(best.Operators) && width < bestWidth {
			best = Agreement{UTC: lower.Add(width / 2).UTC(), Observed: now, Operators: operators, Leap: candidate.leap, oldest: oldest}
			bestWidth = width
		}
	}
	if len(best.Operators) < RequiredOperators {
		return Agreement{}, errors.New("fewer than three time operators have a fresh bounded common interval")
	}
	return best, nil
}
