package serializer

import (
	"encoding/binary"
	"errors"
	"fmt"

	"customer-service/internal/dto"
)

const (
	TagNIK         byte = 0x01
	TagFullName    byte = 0x02
	TagEmail       byte = 0x03
	TagPhoneNumber byte = 0x04
	TagAddress     byte = 0x05
	TagPassword    byte = 0x06
)

// UnpackCustomerTLV mem-parse binary TLV stream menjadi struct EncryptedRegisterCustomerRequest dan rawPassword
// Format wire protocol: [ 1-Byte Tag ] + [ 2-Byte BigEndian Length ] + [ Raw Binary Data ]
func UnpackCustomerTLV(data []byte) (*dto.EncryptedRegisterCustomerRequest, string, error) {
	if len(data) < 3 {
		return nil, "", errors.New("binary payload too short")
	}

	req := &dto.EncryptedRegisterCustomerRequest{}
	var rawPassword string
	offset := 0

	for offset < len(data) {
		if offset+3 > len(data) {
			return nil, "", fmt.Errorf("malformed TLV header at offset %d", offset)
		}

		tag := data[offset]
		length := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3

		if offset+length > len(data) {
			return nil, "", fmt.Errorf("malformed TLV data length at offset %d: expected %d bytes, remaining %d", offset, length, len(data)-offset)
		}

		value := make([]byte, length)
		copy(value, data[offset:offset+length])
		offset += length

		switch tag {
		case TagNIK:
			req.NIK = value
		case TagFullName:
			req.FullName = value
		case TagEmail:
			req.Email = value
		case TagPhoneNumber:
			req.PhoneNumber = value
		case TagAddress:
			req.Address = value
		case TagPassword:
			rawPassword = string(value)
		}
	}

	return req, rawPassword, nil
}
