package capability

import "testing"

func TestGenerateAndValidate(t *testing.T) {
	token, hash, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFormat(token); err != nil {
		t.Fatalf("generated token rejected: %v", err)
	}
	if got := Hash(token); got != hash {
		t.Fatal("token hash mismatch")
	}
}

func TestMalformedToken(t *testing.T) {
	for _, token := range []string{"", "abc", "tsc_bad"} {
		if err := ValidateFormat(token); err == nil {
			t.Fatalf("expected %q to be rejected", token)
		}
	}
}
