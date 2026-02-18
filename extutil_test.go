package main

import "testing"

func TestHasExtension(t *testing.T) {
	tests := []struct {
		path string
		ext  string
		want bool
	}{
		{"/index.php", ".php", true},
		{"/script.js", ".js", true},
		{"/archive.tar.gz", ".gz", true},
		{"/noext", ".php", false},
		{"/start.java", ".js", false},
	}
	for _, tc := range tests {
		got := HasExtension(tc.path, tc.ext)
		if got != tc.want {
			t.Fatalf("HasExtension(%q, %q) = %v, want %v", tc.path, tc.ext, got, tc.want)
		}
	}
}

func TestIsDotNetExtension(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/app.dll", true},
		{"/service.exe", true},
		{"/project.csproj", true},
		{"/library.txt", false},
		{"/noext", false},
	}
	for _, tc := range tests {
		if got := IsDotNetExtension(tc.path); got != tc.want {
			t.Fatalf("IsDotNetExtension(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
