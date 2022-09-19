package salt

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	type args struct {
		from io.Reader
		size uint32
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "reader error",
			args:    args{ErrReader{}, RecommendedSize},
			wantErr: true,
		},
		{
			name: "string reader",
			args: args{strings.NewReader("insecuresalt"), 12},
			want: []byte("insecuresalt"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.from, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}
