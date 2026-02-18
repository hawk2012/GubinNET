package main

// HasExtension checks if the given path ends with the provided extension.
func HasExtension(path string, ext string) bool {
	return len(path) >= len(ext) && path[len(path)-len(ext):] == ext
}

// IsDotNetExtension checks if the path has a .NET-related extension.
func IsDotNetExtension(path string) bool {
	dotNetExts := []string{".dll", ".exe", ".csproj", ".fsproj", ".vbproj"}
	for _, ext := range dotNetExts {
		if HasExtension(path, ext) {
			return true
		}
	}
	return false
}
