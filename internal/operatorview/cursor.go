package operatorview

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

type TimeCursor struct {
	Time time.Time `json:"time"`
	ID   string    `json:"id"`
}

type SequenceCursor struct {
	Sequence uint64 `json:"sequence"`
}

func EncodeTimeCursor(at time.Time, id string) (string, error) {
	id = strings.TrimSpace(id)
	if at.IsZero() || id == "" {
		return "", errors.New("operator cursor requires time and id")
	}
	return encodeCursor(TimeCursor{Time: at.UTC(), ID: id})
}

func DecodeTimeCursor(value string) (TimeCursor, error) {
	var cursor TimeCursor
	if err := decodeCursor(value, &cursor); err != nil {
		return TimeCursor{}, err
	}
	cursor.ID = strings.TrimSpace(cursor.ID)
	if cursor.Time.IsZero() || cursor.ID == "" {
		return TimeCursor{}, errors.New("invalid operator time cursor")
	}
	cursor.Time = cursor.Time.UTC()
	return cursor, nil
}

func EncodeSequenceCursor(sequence uint64) (string, error) {
	if sequence == 0 {
		return "", errors.New("operator audit cursor requires positive sequence")
	}
	return encodeCursor(SequenceCursor{Sequence: sequence})
}

func DecodeSequenceCursor(value string) (SequenceCursor, error) {
	var cursor SequenceCursor
	if err := decodeCursor(value, &cursor); err != nil {
		return SequenceCursor{}, err
	}
	if cursor.Sequence == 0 {
		return SequenceCursor{}, errors.New("invalid operator audit cursor")
	}
	return cursor, nil
}

func encodeCursor(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeCursor(value string, out any) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("operator cursor is empty")
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return errors.New("invalid operator cursor encoding")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errors.New("invalid operator cursor payload")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("invalid operator cursor trailing payload")
	}
	return nil
}
