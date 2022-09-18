package verifier

import "testing"

func TestResult_String(t *testing.T) {
	tests := []struct {
		i    Result
		want string
	}{
		{
			Fail,
			"Fail",
		},
		{
			OK,
			"OK",
		},
		{
			NeedUpdate,
			"NeedUpdate",
		},
		{
			99,
			"Result(99)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.i.String(); got != tt.want {
				t.Errorf("Result.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
