package account_test

import (
	"strconv"
	"testing"

	"coffee-chain-api/account"
)

func TestGender_String(t *testing.T) {
	testCases := []struct {
		input  account.Gender
		expect string
	}{
		{
			input:  account.GenderUnspecified,
			expect: "",
		},
		{
			input:  account.GenderMale,
			expect: "Male",
		},
		{
			input:  account.GenderFemale,
			expect: "Female",
		},
		{
			input:  account.GenderOthers,
			expect: "Others",
		},
	}

	for i, tt := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			out := tt.input.String()
			if out != tt.expect {
				t.Errorf("expecting %s, got %s instead", tt.expect, out)
			}
		})
	}
}
