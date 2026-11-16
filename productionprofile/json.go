// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package productionprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
)

// checkJSON walks the fixed typed schema before decoding. Every declared field
// is required; aliases, duplicates, unknown fields, nulls and trailing data fail.
func checkJSON(raw []byte, typ reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ErrManifest
	}
	switch typ.Kind() {
	case reflect.Struct:
		decoder := json.NewDecoder(bytes.NewReader(raw))
		token, err := decoder.Token()
		if err != nil || token != json.Delim('{') {
			return ErrManifest
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			fields[name] = field.Type
		}
		seen := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			name, ok := token.(string)
			field, known := fields[name]
			if err != nil || !ok || !known || seen[name] {
				return ErrManifest
			}
			seen[name] = true
			var value json.RawMessage
			if decoder.Decode(&value) != nil || checkJSON(value, field) != nil {
				return ErrManifest
			}
		}
		token, err = decoder.Token()
		if err != nil || token != json.Delim('}') || len(seen) != len(fields) {
			return ErrManifest
		}
		if _, err = decoder.Token(); err != io.EOF {
			return ErrManifest
		}
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return ErrManifest
		}
		bound := 4
		if typ.Elem().Kind() == reflect.Uint32 {
			bound = 5
		}
		if len(values) != bound {
			return ErrManifest
		}
		for _, value := range values {
			if err := checkJSON(value, typ.Elem()); err != nil {
				return err
			}
		}
	default:
		target := reflect.New(typ).Interface()
		if json.Unmarshal(raw, target) != nil {
			return ErrManifest
		}
	}
	return nil
}
func decodeTyped(raw []byte, target any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrManifest
	}
	typ := reflect.TypeOf(target).Elem()
	if err := checkJSON(raw, typ); err != nil {
		return err
	}
	if json.Unmarshal(raw, target) != nil {
		return ErrManifest
	}
	return nil
}
func ParseDescriptor(raw []byte) (Descriptor, error) {
	var d Descriptor
	if decodeTyped(raw, &d, MaxDescriptorSize) != nil {
		return Descriptor{}, ErrProfile
	}
	if err := ValidateDescriptor(d); err != nil {
		return Descriptor{}, err
	}
	return d, nil
}
func ParseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if err := decodeTyped(raw, &m, MaxManifestSize); err != nil {
		return Manifest{}, err
	}
	if err := ValidateManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
func MarshalManifest(m Manifest) ([]byte, error) {
	if err := ValidateManifest(m); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > MaxManifestSize {
		return nil, ErrManifest
	}
	return raw, nil
}

// ParseExport currently admits only the two explicitly published candidate
// fixtures; structural descriptor parsing never opens a production issuance path.
func ParseExport(raw []byte) (Export, error) {
	var e Export
	if err := decodeTyped(raw, &e, MaxExportSize); err != nil {
		return Export{}, err
	}
	if _, err := ValidateFixtureExport(context.Background(), e); err != nil {
		return Export{}, err
	}
	return e, nil
}
func MarshalExport(e Export) ([]byte, error) {
	if _, err := ValidateFixtureExport(context.Background(), e); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > MaxExportSize {
		return nil, ErrManifest
	}
	return raw, nil
}
