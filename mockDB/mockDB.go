package mockDB

// Implements a key value store using files. DO NOT USE IN PRODUCTION

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Appends a key value pair to a file
func Append(file string, key string, value string) error {
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write key value pair to file
	if _, err := f.Write([]byte(key + ": " + value + "\n")); err != nil {
		return err
	}

	return nil
}

// Retrieves a value from a file based on a key
func Get(file string, key string) (string, error) {
	// Open file
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Read file
	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		text := fileScanner.Text()
		line := strings.Split(text, ": ")

		if line[0] == key {
			return line[1], nil
		}
	}

	return "", fmt.Errorf("key %s not found", key)
}

// Retrieves all key value pairs from a file as a map
func GetAll(file string) (map[string]string, error) {
	r := make(map[string]string)

	// Open file
	f, err := os.Open(file)
	if err != nil {
		return r, err
	}
	defer f.Close()

	// Read file
	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		text := fileScanner.Text()
		line := strings.Split(text, ": ")

		r[line[0]] = line[1]
	}

	return r, nil
}

// Deletes a key value pair from a file
func Delete(file string, key string) error {
	var newFile string

	// Open file
	f, err := os.Open(file)
	if err != nil {
		return err
	}

	// Read file
	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		text := fileScanner.Text()
		line := strings.Split(text, ": ")

		if line[0] == key {
			continue
		}

		newFile += text + "\n"
	}

	f.Close()

	// Write new file
	f, err = os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	f.WriteString(newFile)

	return nil
}
