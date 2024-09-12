package signing_tool

import "fmt"

type InvalidSizeError struct {
	Got      int
	Expected int
}

func (err InvalidSizeError) Error() string {
	return fmt.Sprintf("unexpected size, got %v, expected %v", err.Got, err.Expected)
}

func checkSize(expected int, got int) error {
	if got == expected {
		return nil
	} else {
		return InvalidSizeError{Got: got, Expected: expected}
	}
}
