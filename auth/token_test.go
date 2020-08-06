package auth

import "testing"

func TestGetTokenTennatID(t *testing.T) {
	fakeToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhY3IiLCJpYXQiOjE1OTYyNjY4ODgsImV4cCI6MTYyNzg4OTI4OCwiYXVkIjoiaHR0cHM6Ly9tYW5hZ2VtZW50LmF6dXJlLmNvbS8iLCJzdWIiOiI1YThlNzE0ZS1jMTBiLTQ4M2ItOGIyMC1jY2U2YjMwZDVjYTIiLCJ0aWQiOiIwMDAwMDAwMC0xMjM0LTU2NzgtNjY2Ni0yMDIwZDAxMTk1MjcifQ.nq2pHcEN_s8ZZnfTaekz3WmhnWOI5sZG_h6x0zFFPTk"
	tid, err := getTokenTenantId(fakeToken)

	if err != nil {
		t.Errorf("parse token failed: %s", err)
		t.FailNow()
	}

	if tid != "00000000-1234-5678-6666-2020d0119527" {
		t.Errorf("unexpected tenant id: %s", tid)
		t.FailNow()
	}
}
