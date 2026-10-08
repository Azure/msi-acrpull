package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

var credentialErrorMetadata = regexp.MustCompile(
	`(?i)\b(?:correlation[ _-]?id|trace[ _-]?id)\s*:\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b\.?` +
		`|\btimestamp\s*:\s*\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b\.?`,
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
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Error            string  `json:"error"`
		ErrorCodes       []int64 `json:"error_codes"`
		ErrorDescription string  `json:"error_description"`
		Message          string  `json:"message"`
	}
	if json.Unmarshal(payload, &responseBody) != nil {
		return err.Error()
	}

	codes := make([]string, 0, len(responseBody.Errors))
	diagnostics := make([]string, 0, len(responseBody.Errors)+2)
	addDiagnostic := func(message string) {
		normalized := strings.Join(strings.Fields(credentialErrorMetadata.ReplaceAllString(message, "")), " ")
		if normalized != "" && !slices.Contains(diagnostics, normalized) {
			diagnostics = append(diagnostics, normalized)
		}
	}
	for _, responseError := range responseBody.Errors {
		if responseError.Code != "" && !slices.Contains(codes, responseError.Code) {
			codes = append(codes, responseError.Code)
		}
		addDiagnostic(responseError.Message)
	}
	addDiagnostic(responseBody.ErrorDescription)
	addDiagnostic(responseBody.Message)
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
	slices.Sort(diagnostics)

	operation := "failed to generate pull credential"
	var generationError credentialGenerationError
	if errors.As(err, &generationError) {
		operation = generationError.operation
	}
	status := fmt.Sprintf("%s: request failed with HTTP status %d: %s", operation, response.StatusCode, strings.Join(codes, ", "))
	if len(diagnostics) != 0 {
		status += ": " + strings.Join(diagnostics, "; ")
	}
	return status
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
