package main

import "regexp"

type OffsetType int

const (
	OffsetFull          OffsetType = iota
	OffsetAfterParent
	OffsetAfterPrematch
	OffsetAfterRegex
)

// Decoder is one compiled <decoder> block.
type Decoder struct {
	Name    string
	Parent  string
	GetNext bool

	// program_name filter
	HasProgName bool
	ProgName    string
	ProgNameRe  *regexp.Regexp

	Prematch       *regexp.Regexp
	PrematchOffset OffsetType

	Regex       *regexp.Regexp  // strict (no flex-spaces)
	RegexFlex   *regexp.Regexp  // with flex-spaces (FOS7 extra-field compat)
	RegexOffset OffsetType

	Order         []string
	PluginDecoder string   // e.g. "JSON_Decoder", "SonicWall_Decoder"
}

// DecoderNode is a node in the parent→child tree.
// Variants holds additional root decoders with the same name but different
// prematch patterns (e.g. all the cisco-ios date-format variants).
// Children is shared: all variants share the same children list.
type DecoderNode struct {
	Decoder  *Decoder
	Variants []*DecoderNode // same-name root decoders (alternative prematch patterns)
	Children []*DecoderNode // child decoders (shared across all variants)
}

// Decoder stores both a strict regex (no flex-spaces) and a flex regex.
// We try strict first; if it fails, we try flex. This lets Cisco ACL-style
// patterns (where spaces are meaningful delimiters) work correctly, while
// Fortigate FOS7 patterns (where extra fields appear between known fields)
// also work via the flex fallback.
