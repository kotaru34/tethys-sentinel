package operatorview

import "testing"

func TestListOptionsNormalized(t *testing.T) {
	tests := []struct {
		name string
		in   ListOptions
		want ListOptions
	}{
		{
			name: "defaults and trims",
			in:   ListOptions{Cursor: "  next  ", Status: " pending "},
			want: ListOptions{Limit: DefaultLimit, Cursor: "next", Status: "pending"},
		},
		{
			name: "caps limit",
			in:   ListOptions{Limit: MaxLimit + 99},
			want: ListOptions{Limit: MaxLimit},
		},
		{
			name: "keeps supported limit",
			in:   ListOptions{Limit: 25},
			want: ListOptions{Limit: 25},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in.Normalized()
			if got != tt.want {
				t.Fatalf("Normalized() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
