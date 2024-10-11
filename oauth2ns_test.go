package oauth2ns

import (
	"testing"
)

func TestMarketDataAPI(t *testing.T) {
	_, err := Run()
	if err != nil {
		t.Fatalf(err.Error())
	}
}
