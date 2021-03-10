package utils

import "os"

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func WriteFile(name string, bytes []byte) bool {
	// Open a new file for writing only
	file, err := os.OpenFile(
		name,
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0666,
	)
	if err != nil {
		PrintErrorLog(err)
		return false
	}
	defer file.Close()

	// Write bytes to file
	_, err = file.Write(bytes)
	if err != nil {
		PrintErrorLog(err)
		return false
	}
	return true
}
