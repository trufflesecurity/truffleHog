package sources

import (
	"encoding/json"
	"fmt"
)

// Ensure CommonSourceUnit implements SourceUnit at compile time.
var _ SourceUnit = CommonSourceUnit{}

// CommonSourceUnit is a common implementation of SourceUnit that Sources can
// use instead of implementing their own types.
type CommonSourceUnit struct {
	ID string `json:"source_unit_id"`
}

// Implement the SourceUnit interface.
func (c CommonSourceUnit) SourceUnitID() string {
	return c.ID
}

// CommonSourceUnitUnmarshaller is an implementation of SourceUnitUnmarshaller
// for the CommonSourceUnit. A source can embed this struct to gain the
// functionality of converting []byte to a CommonSourceUnit.
type CommonSourceUnitUnmarshaller struct{}

// Implement the SourceUnitUnmarshaller interface.
func (c CommonSourceUnitUnmarshaller) UnmarshalSourceUnit(data []byte) (SourceUnit, error) {
	var unit CommonSourceUnit
	if err := json.Unmarshal(data, &unit); err != nil {
		return nil, err
	}
	if unit.ID == "" {
		return nil, fmt.Errorf("not a CommonSourceUnit")
	}
	return unit, nil
}
