package unique

type Set struct {
	seen  map[string]struct{}
	order []string
}

func New() *Set {
	return &Set{seen: make(map[string]struct{})}
}

func (s *Set) Add(value string) bool {
	if value == "" {
		return false
	}
	if _, exists := s.seen[value]; exists {
		return false
	}
	s.seen[value] = struct{}{}
	s.order = append(s.order, value)
	return true
}

func (s *Set) Has(value string) bool {
	_, exists := s.seen[value]
	return exists
}

func (s *Set) Values() []string {
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

func (s *Set) Len() int {
	return len(s.order)
}

func Dedupe(values []string) []string {
	set := New()
	for _, v := range values {
		set.Add(v)
	}
	return set.Values()
}
