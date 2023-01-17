package openidvc

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/tidwall/buntdb"
)

var dbStore *MKVStore

func init() {
	var (
		err error
	)
	dbStore, err = NewMemoryKVStore()
	if err != nil {
		panic(err)
	}
}

// MemoryStore token storage based on buntdb(https://github.com/tidwall/buntdb)
type MKVStore struct {
	*buntdb.DB
}

// NewMemoryKVStore create a store instance based on memory
func NewMemoryKVStore() (*MKVStore, error) {
	db, err := buntdb.Open(":memory:")
	if err != nil {
		return nil, err
	}
	return &MKVStore{db}, nil
}

// Set persist the value with key
func (m *MKVStore) Set(key string, value string, expires time.Duration) error {
	var (
		expiresOption *buntdb.SetOptions = nil
	)
	if strings.TrimSpace(key) == "" {
		return errors.New("empty_key")
	}
	m.DB.Update(func(tx *buntdb.Tx) error {
		if expires > 0 {
			expiresOption = &buntdb.SetOptions{Expires: true, TTL: expires}
		}
		tx.Set(key, value, expiresOption)
		return nil
	})
	return nil
}

func (m *MKVStore) Get(key string) (string, error) {
	var (
		value string
	)
	if strings.TrimSpace(key) == "" {
		return "", buntdb.ErrNotFound
	}
	err := m.DB.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(key)
		if err != nil {
			return err
		}
		value = val
		return nil
	})
	if err != nil {
		return "", err
	}
	return value, nil
}

// remove key
func (m *MKVStore) Remove(key string) error {
	if strings.TrimSpace(key) == "" {
		return buntdb.ErrNotFound
	}
	err := m.DB.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(key)
		return err
	})
	return err
}

func (m *MKVStore) GetAllKeys() ([]string, error) {
	var allKeys []string
	err := m.DB.View(func(tx *buntdb.Tx) error {
		err := tx.Ascend("", func(key, _ string) bool {
			allKeys = append(allKeys, key)
			return true // continue iteration
		})
		return err
	})
	if err != nil {
		return []string{}, nil
	}
	return allKeys, nil
}

func (a *AuthorizationRequest) StoreRequestUri() error {
	authRequestBytes, err := json.Marshal(a)
	if err != nil {
		return errInternalServerError
	}
	key := strings.TrimSpace(a.ClientId) + strings.TrimSpace(a.RequestUri)
	return dbStore.Set(key, string(authRequestBytes), GetServerConfig().ExpirationTime)
}

func (a *AuthorizationRequest) StoreClientRedirectUri() error {
	authRequestBytes, err := json.Marshal(a)
	if err != nil {
		return errInternalServerError
	}
	key := strings.TrimSpace(a.ClientId) + strings.TrimSpace(a.RedirectUri)
	return dbStore.Set(key, string(authRequestBytes), GetServerConfig().ExpirationTime)
}

func (a *AuthorizationResponse) StoreCodeGranted() error {
	authRequestBytes, err := json.Marshal(a)
	if err != nil {
		return errInternalServerError
	}
	return dbStore.Set(a.Code, string(authRequestBytes), GetServerConfig().ExpirationTime)
}

func (a *AuthorizationRequest) StoreClientState() error {
	authRequestBytes, err := json.Marshal(a)
	if err != nil {
		return errInternalServerError
	}
	key := strings.TrimSpace(a.ClientId) + strings.TrimSpace(a.State)
	return dbStore.Set(key, string(authRequestBytes), GetServerConfig().ExpirationTime)
}

func getRecordWithKey(key string, auth interface{}) error {
	authRequestString, err := dbStore.Get(key)
	if err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(authRequestString), &auth); err != nil {
		return err
	}
	return nil
}

func GetByClientRequestUri(clientId string, requestUri string) (*AuthorizationRequest, error) {
	var (
		authRequest AuthorizationRequest
	)
	key := strings.TrimSpace(clientId) + strings.TrimSpace(requestUri)
	if err := getRecordWithKey(key, &authRequest); err != nil {
		return &AuthorizationRequest{}, err
	}
	return &authRequest, nil
}

func GetByClientRedirectUri(clientId string, redirectUri string) (*AuthorizationRequest, error) {
	var (
		authRequest AuthorizationRequest
	)
	key := strings.TrimSpace(clientId) + strings.TrimSpace(redirectUri)
	if err := getRecordWithKey(key, &authRequest); err != nil {
		return &AuthorizationRequest{}, err
	}
	return &authRequest, nil
}

func GetByCodeGranted(code string) (*AuthorizationResponse, error) {
	var (
		authResponse AuthorizationResponse
	)
	if err := getRecordWithKey(code, &authResponse); err != nil {
		return &AuthorizationResponse{}, err
	}
	return &authResponse, nil
}

func GetByClientState(clientId string, state string) (*AuthorizationRequest, error) {
	var (
		authRequest AuthorizationRequest
	)
	key := strings.TrimSpace(clientId) + strings.TrimSpace(state)
	if err := getRecordWithKey(key, &authRequest); err != nil {
		return &AuthorizationRequest{}, err
	}
	return &authRequest, nil
}

// Store the access token values indexed on c_nonce
func (c *CredentialRequest) StoreCredentialRequest() error {
	credRequestBytes, err := json.Marshal(c)
	if err != nil {
		return errInternalServerError
	}
	shaValue := base64.RawStdEncoding.EncodeToString(c.BearerTokenSHA512[:])
	if err := dbStore.Set(shaValue, string(credRequestBytes), GetServerConfig().ExpirationTime); err != nil {
		return err
	}
	// Alseo store the acceptance token with the c_nonce as key
	return dbStore.Set(c.CNonce, string(credRequestBytes), c.CNonceExpiresIn)
}

func GetCredentialRequestSecure(bearerToken string) (*CredentialRequest, error) {
	var (
		credRequest CredentialRequest
	)
	actualSha := sha512.Sum512([]byte(bearerToken))
	key := base64.RawStdEncoding.EncodeToString(actualSha[:])
	if err := getRecordWithKey(key, &credRequest); err != nil {
		return &CredentialRequest{}, err
	}
	if !SecureCompare(credRequest.BearerTokenSHA512, actualSha) {
		return &CredentialRequest{}, errors.New("record_not_found")
	}
	return &credRequest, nil
}

// SecureCompare performs a constant time compare of two strings to limit timing attacks.
func SecureCompare(givenSha [64]byte, actualSha [64]byte) bool {
	return subtle.ConstantTimeCompare(givenSha[:], actualSha[:]) == 1
}

func GetCredentialIssuanceByCNonce(cnonce string) (*CredentialRequest, error) {
	var (
		credRequest CredentialRequest
	)
	key := strings.TrimSpace(cnonce)
	if err := getRecordWithKey(key, &credRequest); err != nil {
		return &CredentialRequest{}, err
	}
	return &credRequest, nil
}
