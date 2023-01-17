package openidvc

import (
	"encoding/json"
	"net/http"
)

// ProviderMetadataRequestHandler handles the request for the provider metatdata
func ProviderMetadataRequestHandler(w http.ResponseWriter, _ *http.Request) {
	providerMetadata := GetProviderMetadata()
	if providerMetadata == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}
	resp, err := json.Marshal(*providerMetadata)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(resp)
}
