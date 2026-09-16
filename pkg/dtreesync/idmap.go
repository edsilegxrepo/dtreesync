// Package dtreesync provides public identity mapping capabilities.
//
// Objectives:
//   - Expose identity mapping loaders and translation structures to public callers.
//   - Support enterprise user, group, UID, GID, and SID transformations.
//
// Core Components:
//   - IdentityMap: Translation table container.
//   - NewIdentityMap / LoadIdentityMapFromFile / LoadIdentityMapFromReader: Creation and loader functions.
//
// Data Flow:
//
//	JSON Configuration -> Loader Function -> IdentityMap -> Passed to RestoreConfig / DiffConfig.
package dtreesync

import (
	"io"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// IdentityMap specifies translation tables for migrating across domains, accounts, or UID/GID spaces.
type IdentityMap = model.IdentityMap

// NewIdentityMap creates an initialized IdentityMap with empty lookup tables.
func NewIdentityMap() *IdentityMap {
	return model.NewIdentityMap()
}

// LoadIdentityMapFromFile reads and parses an IdentityMap JSON file at an absolute path.
func LoadIdentityMapFromFile(filePath string) (*IdentityMap, error) {
	return model.LoadIdentityMapFromFile(filePath)
}

// LoadIdentityMapFromReader parses an IdentityMap from an io.Reader stream.
func LoadIdentityMapFromReader(r io.Reader) (*IdentityMap, error) {
	return model.LoadIdentityMapFromReader(r)
}
