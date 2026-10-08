package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

type credentialGenerationError struct {
	operation string
	err       error
}

func (e credentialGenerationError) Error() string {
	return fmt.Sprintf("%s: %v", e.operation, e.err)
}

func (e credentialGenerationError) Unwrap() error {
	return e.err
}

func credentialStatusMessage(err error) string {
	response := credentialErrorResponse(err)
	if response == nil {
		return err.Error()
	}

	payload, readErr := azruntime.Payload(response)
	if readErr != nil {
		return err.Error()
	}

	var responseBody struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
		Error      string  `json:"error"`
		ErrorCodes []int64 `json:"error_codes"`
	}
	if json.Unmarshal(payload, &responseBody) != nil {
		return err.Error()
	}

	codes := make([]string, 0, len(responseBody.Errors))
	for _, responseError := range responseBody.Errors {
		if responseError.Code != "" && !slices.Contains(codes, responseError.Code) {
			codes = append(codes, responseError.Code)
		}
	}
	if responseBody.Error != "" && !slices.Contains(codes, responseBody.Error) {
		codes = append(codes, responseBody.Error)
	}
	for _, code := range responseBody.ErrorCodes {
		formatted := strconv.FormatInt(code, 10)
		if !slices.Contains(codes, formatted) {
			codes = append(codes, formatted)
		}
	}
	if len(codes) == 0 {
		return err.Error()
	}
	slices.Sort(codes)

	operation := "failed to generate pull credential"
	var generationError credentialGenerationError
	if errors.As(err, &generationError) {
		operation = generationError.operation
	}
	return fmt.Sprintf("%s: request failed with HTTP status %d: %s", operation, response.StatusCode, strings.Join(codes, ", "))
}

func credentialErrorResponse(err error) *http.Response {
	var responseError *azcore.ResponseError
	if errors.As(err, &responseError) {
		return responseError.RawResponse
	}

	var authenticationError *azidentity.AuthenticationFailedError
	if errors.As(err, &authenticationError) {
		return authenticationError.RawResponse
	}

	return nil
}
