package secretbox

import (
	"bytes"
	"testing"
)

func TestCrypto_SHA256HexKnownValue(t *testing.T) {
	result := SHA256Hex("hello")
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if result != expected {
		t.Errorf("SHA256Hex(\"hello\") = %s, want %s", result, expected)
	}
}

func TestCrypto_SHA256HexEmpty(t *testing.T) {
	result := SHA256Hex("")
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if result != expected {
		t.Errorf("SHA256Hex(\"\") = %s, want %s", result, expected)
	}
}

func TestCrypto_HMACDeterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	data := []byte("test message")
	mac1 := HMACSHA256(key, data)
	mac2 := HMACSHA256(key, data)
	if !bytes.Equal(mac1, mac2) {
		t.Error("HMAC should be deterministic")
	}
}

func TestCrypto_HMACDifferentKeys(t *testing.T) {
	key1 := bytes.Repeat([]byte{0xAA}, 32)
	key2 := bytes.Repeat([]byte{0xBB}, 32)
	data := []byte("test")
	if bytes.Equal(HMACSHA256(key1, data), HMACSHA256(key2, data)) {
		t.Error("different keys should produce different HMACs")
	}
}

func TestCrypto_HMACDifferentData(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 32)
	mac1 := HMACSHA256(key, []byte("hello"))
	mac2 := HMACSHA256(key, []byte("world"))
	if bytes.Equal(mac1, mac2) {
		t.Error("different data should produce different HMACs")
	}
}

func TestCrypto_ConstantTimeEqualTrue(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5}
	if !ConstantTimeEqual(a, a) {
		t.Error("equal data should be equal")
	}
}

func TestCrypto_ConstantTimeEqualFalse(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5}
	b := []byte{1, 2, 3, 4, 6}
	if ConstantTimeEqual(a, b) {
		t.Error("different data should not be equal")
	}
}

func TestCrypto_ConstantTimeEqualDifferentLengths(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{1, 2, 3, 4}
	if ConstantTimeEqual(a, b) {
		t.Error("different length data should not be equal")
	}
}

func TestCrypto_ConstantTimeEqualEmpty(t *testing.T) {
	if !ConstantTimeEqual([]byte{}, []byte{}) {
		t.Error("empty data should be equal")
	}
}
