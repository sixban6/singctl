package test

import (
	"testing"

	"singctl/internal/singbox"
)

func TestParseSingBoxVersionOutput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "标准格式",
			input: "sing-box version 1.12.0",
			want:  "1.12.0",
		},
		{
			name:  "RC版本",
			input: "sing-box version 1.13.0-rc.1",
			want:  "1.13.0-rc.1",
		},
		{
			name:  "多行输出",
			input: "sing-box version 1.12.0\n\nEnvironment: CGO enabled, go1.24.1, darwin/arm64\nTags: with_gvisor",
			want:  "1.12.0",
		},
		{
			name:  "纯版本号",
			input: "1.12.0",
			want:  "1.12.0",
		},
		{
			name:  "带前导空格",
			input: "  sing-box version 1.12.0  ",
			want:  "1.12.0",
		},
		{
			name:    "空输入",
			input:   "",
			wantErr: true,
		},
		{
			name:    "空白输入",
			input:   "  \n  ",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := singbox.ParseSingBoxVersionOutput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSingBoxVersionOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseSingBoxVersionOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}
