package serializer_test

import (
	"encoding/binary"
	"testing"

	"customer-service/internal/delivery/http/serializer"
)

func TestUnpackCustomerTLV_Success(t *testing.T) {
	// Buat payload dummy TLV
	var buf []byte

	appendField := func(tag byte, val []byte) {
		buf = append(buf, tag)
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(len(val)))
		buf = append(buf, lenBytes...)
		buf = append(buf, val...)
	}

	nik := []byte("encrypted_nik_bytes")
	fullName := []byte("encrypted_fullname_bytes")
	email := []byte("encrypted_email_bytes")
	phone := []byte("encrypted_phone_bytes")
	address := []byte("encrypted_address_bytes")
	pwd := []byte("SuperSecretPass123!")

	appendField(serializer.TagNIK, nik)
	appendField(serializer.TagFullName, fullName)
	appendField(serializer.TagEmail, email)
	appendField(serializer.TagPhoneNumber, phone)
	appendField(serializer.TagAddress, address)
	appendField(serializer.TagPassword, pwd)

	req, password, err := serializer.UnpackCustomerTLV(buf)
	if err != nil {
		t.Fatalf("UnpackCustomerTLV failed: %v", err)
	}

	if string(req.NIK) != string(nik) {
		t.Errorf("expected NIK %s, got %s", nik, req.NIK)
	}
	if string(req.FullName) != string(fullName) {
		t.Errorf("expected FullName %s, got %s", fullName, req.FullName)
	}
	if string(req.Email) != string(email) {
		t.Errorf("expected Email %s, got %s", email, req.Email)
	}
	if string(req.PhoneNumber) != string(phone) {
		t.Errorf("expected Phone %s, got %s", phone, req.PhoneNumber)
	}
	if string(req.Address) != string(address) {
		t.Errorf("expected Address %s, got %s", address, req.Address)
	}
	if password != string(pwd) {
		t.Errorf("expected Password %s, got %s", pwd, password)
	}
}

func TestUnpackCustomerTLV_Malformed(t *testing.T) {
	// Terlalu pendek
	_, _, err := serializer.UnpackCustomerTLV([]byte{0x01})
	if err == nil {
		t.Error("expected error for too short payload, got nil")
	}

	// Length overflow
	corrupted := []byte{serializer.TagNIK, 0x00, 0x10, 0x01, 0x02}
	_, _, err = serializer.UnpackCustomerTLV(corrupted)
	if err == nil {
		t.Error("expected error for malformed TLV length, got nil")
	}
}
