package unique

import "testing"

func TestDedupePreservesOrder(t *testing.T) {
	t.Parallel()

	got := Dedupe([]string{"b", "a", "b", "", "c", "a"})
	want := []string{"b", "a", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestSetAdd(t *testing.T) {
	t.Parallel()

	s := New()
	if !s.Add("x") {
		t.Fatal("first add should succeed")
	}
	if s.Add("x") {
		t.Fatal("duplicate add should fail")
	}
	if s.Add("") {
		t.Fatal("empty add should fail")
	}
	if s.Len() != 1 {
		t.Fatalf("len=%d", s.Len())
	}
}
