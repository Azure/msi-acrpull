package main

import (
	"flag"
	"reflect"
	"testing"
)

func TestCommaSeparatedValues(t *testing.T) {
	testCases := []struct {
		name  string
		value string
		want  []string
	}{
		{
			name:  "empty value",
			value: "",
		},
		{
			name:  "single value",
			value: "azurecr.io",
			want:  []string{"azurecr.io"},
		},
		{
			name:  "trims and skips empty items",
			value: " azurecr.io, , azurecr.cn ",
			want:  []string{"azurecr.io", "azurecr.cn"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := commaSeparatedValues(testCase.value)
			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("expected %#v, got %#v", testCase.want, got)
			}
		})
	}
}

func TestCommaSeparatedStringSliceFlag(t *testing.T) {
	var values commaSeparatedStringSlice
	flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
	flagSet.Var(&values, "allowed-acr-server-suffixes", "")

	err := flagSet.Parse([]string{
		"--allowed-acr-server-suffixes=azurecr.io,azurecr.cn",
		"--allowed-acr-server-suffixes=azurecr.de",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	want := []string{"azurecr.io", "azurecr.cn", "azurecr.de"}
	if !reflect.DeepEqual([]string(values), want) {
		t.Fatalf("expected %#v, got %#v", want, []string(values))
	}
}
