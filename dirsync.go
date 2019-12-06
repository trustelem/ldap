package ldap

import (
	"errors"
	"fmt"
)

// SearchWithDirSync accepts a search request and a sync cookie
func (l *Conn) SearchWithDirSync(searchRequest *SearchRequest, cookie []byte, flags uint32) (*SearchResult, []byte, error) {
	var dirSyncControl *ControlMicrosoftDirSync

	control := FindControl(searchRequest.Controls, ControlTypeMicrosoftDirSync)
	if control == nil {
		dirSyncControl = NewControlMicrosoftDirSync()
		searchRequest.Controls = append(searchRequest.Controls, dirSyncControl)
	} else {
		castControl, ok := control.(*ControlMicrosoftDirSync)
		if !ok {
			return nil, nil, fmt.Errorf("expected dirSync control to be of type *ControlMicrosoftDirSync, got %v", control)
		}
		dirSyncControl = castControl
	}

	dirSyncControl.SetCookie(cookie)
	dirSyncControl.Flags = flags

	var newCookie []byte
	searchResult := new(SearchResult)
	for {
		result, err := l.Search(searchRequest)
		if err != nil {
			return searchResult, nil, err
		}
		if result == nil {
			return searchResult, nil, NewError(ErrorNetwork, errors.New("ldap: packet not received"))
		}

		for _, entry := range result.Entries {
			searchResult.Entries = append(searchResult.Entries, entry)
		}
		for _, referral := range result.Referrals {
			searchResult.Referrals = append(searchResult.Referrals, referral)
		}
		for _, control := range result.Controls {
			searchResult.Controls = append(searchResult.Controls, control)
		}

		l.Debug.Printf("Looking for DirSync Control...")
		dirSyncResult := FindControl(result.Controls, ControlTypeMicrosoftDirSync)
		if dirSyncResult == nil {
			return searchResult, nil, NewError(ErrorNetwork, errors.New("ldap: response is missing DirSync control"))
		}

		dirSyncResponse := dirSyncResult.(*ControlMicrosoftDirSyncResponse)
		newCookie = dirSyncResponse.Cookie
		if len(newCookie) == 0 {
			return searchResult, nil, NewError(ErrorNetwork, errors.New("ldap: empty cookie in DirSync control response"))
		}
		if dirSyncResponse.MoreResults == 0 {
			break
		}
		dirSyncControl.SetCookie(newCookie)
	}

	return searchResult, newCookie, nil
}
