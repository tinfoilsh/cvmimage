package main

import (
	"strings"
	"testing"
)

func TestIsHexHash(t *testing.T) {
	t.Parallel()

	for _, value := range []string{strings.Repeat("0", 64), strings.Repeat("abcdef12", 8)} {
		if !isHexHash(value) {
			t.Errorf("isHexHash(%q) = false", value)
		}
	}
	for _, value := range []string{"", strings.Repeat("0", 63), strings.Repeat("0", 65), strings.Repeat("A", 64), strings.Repeat("é", 32)} {
		if isHexHash(value) {
			t.Errorf("isHexHash(%q) = true", value)
		}
	}

	candidate := []byte(strings.Repeat("0", 64))
	for index := range candidate {
		for character := 0; character <= 255; character++ {
			candidate[index] = byte(character)
			if got, want := isHexHash(string(candidate)), testLowerHex(byte(character)); got != want {
				t.Fatalf("isHexHash with byte %#x at %d = %t, want %t", character, index, got, want)
			}
		}
		candidate[index] = '0'
	}
}

func TestIsRegistry(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"a", "0", "a0", "ghcr.io", "a..b", "a--b", "a.-.b", strings.Repeat("z", 4096)} {
		if !isRegistry(value) {
			t.Errorf("isRegistry(%q) = false", value)
		}
	}
	for _, value := range []string{"", ".a", "-a", "a.", "a-", "A", "a_b", "a:b", "a/b", "a\n", "é"} {
		if isRegistry(value) {
			t.Errorf("isRegistry(%q) = true", value)
		}
	}

	for character := 0; character <= 255; character++ {
		byteValue := byte(character)
		if got, want := isRegistry(string([]byte{byteValue})), testLowerAlphanumeric(byteValue); got != want {
			t.Fatalf("isRegistry single byte %#x = %t, want %t", character, got, want)
		}
		if got, want := isRegistry(string([]byte{byteValue, 'b'})), testLowerAlphanumeric(byteValue); got != want {
			t.Fatalf("isRegistry first byte %#x = %t, want %t", character, got, want)
		}
		wantInterior := testLowerAlphanumeric(byteValue) || byteValue == '.' || byteValue == '-'
		if got := isRegistry(string([]byte{'a', byteValue, 'b'})); got != wantInterior {
			t.Fatalf("isRegistry interior byte %#x = %t, want %t", character, got, wantInterior)
		}
		if got, want := isRegistry(string([]byte{'a', byteValue})), testLowerAlphanumeric(byteValue); got != want {
			t.Fatalf("isRegistry final byte %#x = %t, want %t", character, got, want)
		}
	}
}

func TestIsSecretName(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"a", "Z", "_", "a0", "_A9", strings.Repeat("A", 4096)} {
		if !isSecretName(value) {
			t.Errorf("isSecretName(%q) = false", value)
		}
	}
	for _, value := range []string{"", "0", "-", "a-b", "a.b", "a b", "a\n", "é", "_é"} {
		if isSecretName(value) {
			t.Errorf("isSecretName(%q) = true", value)
		}
	}

	for character := 0; character <= 255; character++ {
		byteValue := byte(character)
		wantFirst := testASCIIAlpha(byteValue) || byteValue == '_'
		if got := isSecretName(string([]byte{byteValue})); got != wantFirst {
			t.Fatalf("isSecretName first byte %#x = %t, want %t", character, got, wantFirst)
		}
		wantRemaining := wantFirst || testDigit(byteValue)
		if got := isSecretName(string([]byte{'A', byteValue})); got != wantRemaining {
			t.Fatalf("isSecretName remaining byte %#x = %t, want %t", character, got, wantRemaining)
		}
	}
}

func testLowerHex(character byte) bool {
	return testDigit(character) || character >= 'a' && character <= 'f'
}

func testLowerAlphanumeric(character byte) bool {
	return testDigit(character) || character >= 'a' && character <= 'z'
}

func testASCIIAlpha(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
}

func testDigit(character byte) bool {
	return character >= '0' && character <= '9'
}
