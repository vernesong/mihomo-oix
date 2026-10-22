package oix

import (
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The tree lives only for this load. The persistent profile remains encrypted,
// and the DNS snapshots do not retain the full parsed configuration.
func (config *fetchedConfig) profileDocument() (*yaml.Node, error) {
	if config.document == nil {
		var document yaml.Node
		if err := yaml.Unmarshal(config.plain, &document); err != nil {
			return nil, errors.New("managed profile is not a YAML mapping")
		}
		config.document = &document
	}
	document := config.document
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("managed profile is not a YAML mapping")
	}
	return document, nil
}

func mergeProfile(managed *yaml.Node, overlay []byte) (*yaml.Node, error) {
	var local yaml.Node
	if err := yaml.Unmarshal(overlay, &local); err != nil {
		return nil, fmt.Errorf("local config: %w", err)
	}
	// Ordinary generated profiles have string keys and no aliases. Keep those
	// nodes all the way to runtime decoding instead of emitting and parsing YAML.
	// Complex YAML keeps the old map merge semantics: aliases are independent
	// values, merge keys are expanded, and duplicate keys are rejected.
	if local.Kind == yaml.DocumentNode && len(local.Content) == 1 &&
		local.Content[0].Kind == yaml.MappingNode && simpleProfileNode(managed) && simpleProfileNode(&local) {
		mergeProfileNodes(managed.Content[0], local.Content[0])
		if err := sortProfileDNSPolicies(managed.Content[0]); err != nil {
			return nil, err
		}
		return managed, nil
	}
	return mergeProfileMaps(managed, &local)
}

func simpleProfileNode(node *yaml.Node) bool {
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return false
	}
	if node.Kind == yaml.ScalarNode {
		// The former map-to-YAML step canonicalized numbers, booleans and
		// timestamps. Keep unusual spellings on that path so typed string
		// fields still receive the same value (e.g. 0xFF becomes "255").
		switch node.Tag {
		case "!!str", "!!null":
			return true
		case "!!bool":
			return node.Value == "true" || node.Value == "false"
		case "!!int":
			if node.Value == "0" {
				return true
			}
			digits := strings.TrimPrefix(node.Value, "-")
			if len(digits) == 0 || digits[0] < '1' || digits[0] > '9' {
				return false
			}
			for _, digit := range digits {
				if digit < '0' || digit > '9' {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	if node.Kind == yaml.MappingNode {
		keys := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return false
			}
			if _, exists := keys[key.Value]; exists {
				return false
			}
			keys[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if !simpleProfileNode(child) {
			return false
		}
	}
	return true
}

// Both trees have already been checked for aliases and duplicate string keys.
// Mappings merge recursively; lists, scalars and null replace the old value.
func mergeProfileNodes(dst, src *yaml.Node) {
	indices := make(map[string]int, len(dst.Content)/2)
	for i := 0; i < len(dst.Content); i += 2 {
		indices[dst.Content[i].Value] = i + 1
	}
	for i := 0; i < len(src.Content); i += 2 {
		key, value := src.Content[i], src.Content[i+1]
		if index, exists := indices[key.Value]; exists {
			if dst.Content[index].Kind == yaml.MappingNode && value.Kind == yaml.MappingNode {
				mergeProfileNodes(dst.Content[index], value)
			} else {
				dst.Content[index] = value
			}
		} else {
			indices[key.Value] = len(dst.Content) + 1
			dst.Content = append(dst.Content, key, value)
		}
	}
}

func mergeProfileMaps(managed, local *yaml.Node) (*yaml.Node, error) {
	var config map[string]any
	if err := managed.Decode(&config); err != nil || config == nil {
		return nil, errors.New("managed profile is not a YAML mapping")
	}
	var overrides map[string]any
	if err := local.Decode(&overrides); err != nil {
		return nil, fmt.Errorf("local config: %w", err)
	}
	mergeMaps(config, overrides)
	var document yaml.Node
	// Encode retains the original YAML library's scalar conversions on this
	// compatibility path; the ordinary path above does not re-encode anything.
	if err := document.Encode(config); err != nil {
		return nil, err
	}
	return &document, nil
}

func mergeMaps(dst, src map[string]any) {
	for key, value := range src {
		if srcMap, ok := value.(map[string]any); ok {
			if dstMap, ok := dst[key].(map[string]any); ok {
				mergeMaps(dstMap, srcMap)
				continue
			}
		}
		dst[key] = value
	}
}

// DNS policies decode into ordered maps. Preserve the YAML map encoder's
// ordering, including its numeric key comparison, without serializing their
// values or the rest of the profile.
func sortProfileDNSPolicies(root *yaml.Node) error {
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value != "dns" || root.Content[i+1].Kind != yaml.MappingNode {
			continue
		}
		dns := root.Content[i+1]
		for j := 0; j < len(dns.Content); j += 2 {
			key, value := dns.Content[j], dns.Content[j+1]
			if (key.Value != "nameserver-policy" && key.Value != "proxy-server-nameserver-policy") || value.Kind != yaml.MappingNode || len(value.Content) < 4 {
				continue
			}
			indices := make(map[string]int, len(value.Content)/2)
			for k := 0; k < len(value.Content); k += 2 {
				indices[value.Content[k].Value] = k
			}
			var sorted yaml.Node
			if err := sorted.Encode(indices); err != nil {
				return err
			}
			for k := 0; k < len(sorted.Content); k += 2 {
				index := indices[sorted.Content[k].Value]
				sorted.Content[k], sorted.Content[k+1] = value.Content[index], value.Content[index+1]
			}
			value.Content = sorted.Content
		}
	}
	return nil
}
