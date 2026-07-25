package main

import (
	"crypto/sha256"
	"encoding/hex"
)

func isHexHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if !isLowerHex(value[index]) {
			return false
		}
	}
	return true
}

func isRegistry(value string) bool {
	if value == "" || !isLowerAlphanumeric(value[0]) {
		return false
	}
	if len(value) == 1 {
		return true
	}
	if !isLowerAlphanumeric(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		character := value[index]
		if !isLowerAlphanumeric(character) && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func isSecretName(value string) bool {
	if value == "" || (!isASCIIAlpha(value[0]) && value[0] != '_') {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !isASCIIAlpha(value[index]) && !isDigit(value[index]) && value[index] != '_' {
			return false
		}
	}
	return true
}

func isLowerHex(character byte) bool {
	return isDigit(character) || character >= 'a' && character <= 'f'
}

func isLowerAlphanumeric(character byte) bool {
	return isDigit(character) || character >= 'a' && character <= 'z'
}

func isASCIIAlpha(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
}

func isDigit(character byte) bool {
	return character >= '0' && character <= '9'
}

// sha256Hash computes the SHA256 hash of data and returns hex string
func sha256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
