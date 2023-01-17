package openidvc

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
)

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func (o *optionalParameters) checkRequired(requiredParameters []string) error {
	values := reflect.ValueOf(o)
	typesOf := values.Type()
	// Traverse through all the fields of a struct.
	if values.Kind() == reflect.Struct {
		for i := 0; i < values.NumField(); i++ {
			if contains(requiredParameters, typesOf.Field(i).Name) {
				if values.Field(i).Interface() == nil {
					return fmt.Errorf("%s is required", typesOf.Field(i).Name)
				}
			}
		}
	}
	return nil
}

func httpPostForm(uri url.URL) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	response, err := client.PostForm(uri.String(), uri.Query())
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	switch response.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusFound:
		return bodyBytes, nil
	default:
		var errorResponse ErrorResponse
		if err = json.Unmarshal(bodyBytes, &errorResponse); err != nil {
			return nil, err
		}
		return bodyBytes, errors.New(http.StatusText(response.StatusCode))
	}
}

func generateRandomBytes(len int) ([]byte, error) {
	randomBytes := make([]byte, len)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func generateNonce() (string, error) {
	nonceBytes, err := generateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(nonceBytes), nil
}
