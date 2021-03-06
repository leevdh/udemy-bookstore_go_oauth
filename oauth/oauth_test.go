package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOauthConstants(t *testing.T) {
	assert.EqualValues(t, headerXPublic, "X-Public")
	assert.EqualValues(t, headerXClientID, "X-Client-Id")
	assert.EqualValues(t, headerXCallerID, "X-User-Id")
	assert.EqualValues(t, paramAccessToken, "access_token")
}
