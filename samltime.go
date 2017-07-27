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
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that uses the xsd:duration format for text
// marshalling and unmarshalling.
type Duration time.Duration

var TimeNow = func() time.Time { return time.Now().UTC() }

// MarshalText implements the encoding.TextMarshaler interface.
func (d Duration) MarshalText() ([]byte, error) {
	if d == 0 {
		return nil, nil
	}

	out := "PT"
	if d < 0 {
		d *= -1
		out = "-" + out
	}

	h := time.Duration(d) / time.Hour
	m := time.Duration(d) % time.Hour / time.Minute
	s := time.Duration(d) % time.Minute / time.Second
	ns := time.Duration(d) % time.Second
	if h > 0 {
		out += fmt.Sprintf("%dH", h)
	}
	if m > 0 {
		out += fmt.Sprintf("%dM", m)
	}
	if s > 0 || ns > 0 {
		out += fmt.Sprintf("%d", s)
		if ns > 0 {
			out += strings.TrimRight(fmt.Sprintf(".%09d", ns), "0")
		}
		out += "S"
	}

	return []byte(out), nil
}

const (
	day   = 24 * time.Hour
	month = 30 * day  // Assumed to be 30 days.
	year  = 365 * day // Assumed to be non-leap year.
)

var (
	durationRegexp     = regexp.MustCompile(`^(-?)P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(.+))?$`)
	durationTimeRegexp = regexp.MustCompile(`^(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?$`)
)

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (d *Duration) UnmarshalText(text []byte) error {
	if text == nil {
		*d = 0
		return nil
	}

	var (
		out  time.Duration
		sign time.Duration = 1
	)
	match := durationRegexp.FindStringSubmatch(string(text))
	if match == nil || strings.Join(match[2:6], "") == "" {
		return fmt.Errorf("invalid duration (%s)", text)
	}
	if match[1] == "-" {
		sign = -1
	}
	if match[2] != "" {
		y, err := strconv.Atoi(match[2])
		if err != nil {
			return fmt.Errorf("invalid duration years (%s): %s", text, err)
		}
		out += time.Duration(y) * year
	}
	if match[3] != "" {
		m, err := strconv.Atoi(match[3])
		if err != nil {
			return fmt.Errorf("invalid duration months (%s): %s", text, err)
		}
		out += time.Duration(m) * month
	}
	if match[4] != "" {
		d, err := strconv.Atoi(match[4])
		if err != nil {
			return fmt.Errorf("invalid duration days (%s): %s", text, err)
		}
		out += time.Duration(d) * day
	}
	if match[5] != "" {
		match := durationTimeRegexp.FindStringSubmatch(match[5])
		if match == nil {
			return fmt.Errorf("invalid duration (%s)", text)
		}
		if match[1] != "" {
			h, err := strconv.Atoi(match[1])
			if err != nil {
				return fmt.Errorf("invalid duration hours (%s): %s", text, err)
			}
			out += time.Duration(h) * time.Hour
		}
		if match[2] != "" {
			m, err := strconv.Atoi(match[2])
			if err != nil {
				return fmt.Errorf("invalid duration minutes (%s): %s", text, err)
			}
			out += time.Duration(m) * time.Minute
		}
		if match[3] != "" {
			s, err := strconv.ParseFloat(match[3], 64)
			if err != nil {
				return fmt.Errorf("invalid duration seconds (%s): %s", text, err)
			}
			out += time.Duration(s * float64(time.Second))
		}
	}

	*d = Duration(sign * out)
	return nil
}

type RelaxedTime time.Time

const timeFormat = "2006-01-02T15:04:05.999Z07:00"

func (m RelaxedTime) MarshalText() ([]byte, error) {
	// According to section 1.2.2 of the OASIS SAML 1.1 spec, we can't trust
	// other applications to handle time resolution finer than a millisecond.
	//
	// The time MUST be expressed in UTC.
	return []byte(m.String()), nil
}

func (m RelaxedTime) String() string {
	return time.Time(m).Round(time.Millisecond).UTC().Format(timeFormat)
}

func (m *RelaxedTime) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*m = RelaxedTime(time.Time{})
		return nil
	}
	t, err1 := time.Parse(time.RFC3339, string(text))
	if err1 == nil {
		t = t.Round(time.Millisecond)
		*m = RelaxedTime(t)
		return nil
	}

	t, err2 := time.Parse(time.RFC3339Nano, string(text))
	if err2 == nil {
		t = t.Round(time.Millisecond)
		*m = RelaxedTime(t)
		return nil
	}

	t, err2 = time.Parse("2006-01-02T15:04:05.999999999", string(text))
	if err2 == nil {
		t = t.Round(time.Millisecond)
		*m = RelaxedTime(t)
		return nil
	}

	return err1
}
