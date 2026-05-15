package security

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type argon2idHash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	hash        []byte
}

func VerifyPassword(password string, encodedHash string) bool {
	parsed, err := parseArgon2idHash(encodedHash)
	if err != nil {
		return false
	}
	hash := argon2.IDKey(
		[]byte(password),
		parsed.salt,
		parsed.iterations,
		parsed.memory,
		parsed.parallelism,
		uint32(len(parsed.hash)),
	)
	return subtle.ConstantTimeCompare(hash, parsed.hash) == 1
}

func parseArgon2idHash(encodedHash string) (argon2idHash, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return argon2idHash{}, fmt.Errorf("invalid argon2id hash")
	}

	params, err := parseArgon2Params(parts[3])
	if err != nil {
		return argon2idHash{}, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argon2idHash{}, fmt.Errorf("decode salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argon2idHash{}, fmt.Errorf("decode hash: %w", err)
	}
	params.salt = salt
	params.hash = hash
	return params, nil
}

func parseArgon2Params(encodedParams string) (argon2idHash, error) {
	var params argon2idHash
	for _, part := range strings.Split(encodedParams, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return argon2idHash{}, fmt.Errorf("invalid argon2id parameter")
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return argon2idHash{}, fmt.Errorf("parse argon2id parameter %s: %w", key, err)
		}
		switch key {
		case "m":
			params.memory = uint32(parsed)
		case "t":
			params.iterations = uint32(parsed)
		case "p":
			if parsed > 255 {
				return argon2idHash{}, fmt.Errorf("argon2id parallelism is too large")
			}
			params.parallelism = uint8(parsed)
		default:
			return argon2idHash{}, fmt.Errorf("unknown argon2id parameter")
		}
	}
	if params.memory == 0 || params.iterations == 0 || params.parallelism == 0 {
		return argon2idHash{}, fmt.Errorf("missing argon2id parameter")
	}
	return params, nil
}
