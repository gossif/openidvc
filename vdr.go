package openidvc

import (
	"errors"
	"strings"
	"sync"
)

// didMethodItem stores the method name and the pointer to the struct
// that implements the interface for a decentralized indentifier
type didMethodItem struct {
	methodName      string
	methodInterface DecetralizedIdentifier
}

// didMethodSlice is the slice of registered methods
type didMethodSlice []didMethodItem

// didMethodRegistry stores all the registered methods
type didMethodRegistry struct {
	registeredMethods didMethodSlice
}

// DecetralizedIdentifier is the interface for a decentralized identifier
type DecetralizedIdentifier interface {
	ResolveDid(did string) (interface{}, error)
}

// didRegistry holds the registered methods
var (
	once        sync.Once
	didRegistry *didMethodRegistry
)

// NewDecetralizedIdentifierRegistry initializes the registration of did methods
// this function is implemented as a singleton
func NewDecetralizedIdentifierRegistry() *didMethodRegistry {
	once.Do(func() {
		didRegistry = &didMethodRegistry{}
	})
	return didRegistry
}

// RegisterMethod registrates the method and the struct that implements the interface for a decentralized identifier
func (r *didMethodRegistry) RegisterMethod(methodName string, methodInterface DecetralizedIdentifier) {
	r.registeredMethods = append(r.registeredMethods, didMethodItem{methodName: methodName, methodInterface: methodInterface})
}

// ResolveDid resolves the did for the method name in the did
func (r *didMethodRegistry) ResolveDid(did string) (interface{}, error) {
	didSplitString := strings.Split(did, ":")
	if len(didSplitString) >= 3 {
		methodName := didSplitString[1]
		for _, v := range r.registeredMethods {
			if v.methodName == methodName {
				return v.methodInterface.ResolveDid(did)
			}
		}
	}
	return nil, errors.New("unknown_method")
}
