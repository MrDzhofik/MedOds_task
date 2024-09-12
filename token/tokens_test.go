package token

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
)

func TestGenerateJWT(t *testing.T) {
	userID := "1"
	ip := "127.0.0.1"

	str, err := generateJWT(userID, ip)

	assert.NotEmpty(t, str)

	assert.NoError(t, err)
}

func TestGenerateRT(t *testing.T) {
	str, err := generateRT()

	assert.NotEmpty(t, str)

	assert.NoError(t, err)
}

func TestSaveRT(t *testing.T) {
	mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close(context.Background())

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE tokens").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectExec("INSERT INTO tokens").
		WithArgs(2, 3).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectCommit()

	assert.NoError(t, err)

	assert.NoError(t, err)
}

func TestGetIP(t *testing.T) {
	testCases := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{
			name:       "valid IP",
			remoteAddr: "192.168.1.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:       "valid IP with port",
			remoteAddr: "10.0.0.1:1234",
			expected:   "10.0.0.1",
		},
		{
			name:       "invalid RemoteAddr",
			remoteAddr: "invalid_addr",
			expected:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tc.remoteAddr

			result := getIP(req)
			if result != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, result)
			}
		})
	}
}
