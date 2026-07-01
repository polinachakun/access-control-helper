package generator

import (
	"fmt"
	"io"
	"os"
	"strings"

	"access-control-helper/internal/ir"
)

// Generator produces Alloy specifications from an IR Config.
type Generator struct {
	config     *ir.Config
	sourceFile string

	tags    map[string]bool
	vpces   map[string]bool
	actions map[string]bool

	principals       []PrincipalEntry
	bucketNames      []string
	actionNames      []string
	principalDisplay map[string]string
	bucketDisplay    map[string]string

	// wildcardLayers tracks which evaluation layers had wildcard actions (e.g. s3:*).
	wildcardLayers []string
}

// NewGenerator creates a new Generator.
func NewGenerator(config *ir.Config, sourceFile string) *Generator {
	return &Generator{
		config:           config,
		sourceFile:       sourceFile,
		tags:             make(map[string]bool),
		vpces:            make(map[string]bool),
		actions:          make(map[string]bool),
		principalDisplay: make(map[string]string),
		bucketDisplay:    make(map[string]string),
	}
}

// GenerateToFile writes the Alloy specification to outputPath.
func (g *Generator) GenerateToFile(outputPath string) error {
	g.collectValues()
	data := g.buildTemplateData()
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()
	if err := RenderTemplate(f, data); err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}
	return nil
}

// GenerateToWriter writes the Alloy specification to any io.Writer.
func (g *Generator) GenerateToWriter(w io.Writer) error {
	g.collectValues()
	data := g.buildTemplateData()
	return RenderTemplate(w, data)
}

// WildcardLayers returns the ordered list of evaluation layer labels where a
// wildcard action (e.g. s3:*) was detected. Empty when all actions are explicit.
func (g *Generator) WildcardLayers() []string { return g.wildcardLayers }

// WildcardFate describes what happens to S3 actions not explicitly analyzed
// when one or more policy layers grant s3:*.
type WildcardFate struct {
	HasWildcard      bool
	BlockingLayer    string // first layer that blocks unlisted actions, e.g. "Layer 6 (permission boundary)"
	BlockingReason   string // e.g. "permission boundary restricts to [s3:GetObject] only"
	EffectivelyAllow bool   // true when wildcard is present and no blocking layer exists
}

// ComputeWildcardFate determines what happens to unlisted S3 actions by inspecting
// each evaluation layer in AWS order. Must be called after GenerateToFile/Writer.
func (g *Generator) ComputeWildcardFate() WildcardFate {
	if len(g.wildcardLayers) == 0 {
		return WildcardFate{}
	}

	fate := WildcardFate{HasWildcard: true}

	// Layer 1: explicit deny for all S3 actions in identity or bucket policy.
	for _, r := range g.config.Roles {
		if HasWildcardActions(r.RoleDenyActions) {
			fate.BlockingLayer = "Layer 1"
			fate.BlockingReason = "identity policy explicitly denies all S3 actions"
			return fate
		}
	}
	for _, u := range g.config.Users {
		if HasWildcardActions(u.UserDenyActions) {
			fate.BlockingLayer = "Layer 1"
			fate.BlockingReason = "identity policy explicitly denies all S3 actions"
			return fate
		}
	}
	for _, bp := range g.config.BucketPolicies {
		if HasWildcardActions(bp.DenyActions) {
			fate.BlockingLayer = "Layer 1"
			fate.BlockingReason = "bucket policy explicitly denies all S3 actions"
			return fate
		}
	}

	// Layer 2: RCP with explicit (non-wildcard) allow list.
	for _, op := range g.config.RCPs() {
		if len(op.AllowActions) > 0 && !HasWildcardActions(op.AllowActions) {
			explicit := ExpandAnalyzableActions(op.AllowActions)
			fate.BlockingLayer = "Layer 2 (RCP)"
			fate.BlockingReason = fmt.Sprintf("RCP restricts to [%s] only", strings.Join(explicit, ", "))
			return fate
		}
	}

	// Layer 3: SCP with explicit (non-wildcard) allow list.
	for _, op := range g.config.SCPs() {
		if len(op.AllowActions) > 0 && !HasWildcardActions(op.AllowActions) {
			explicit := ExpandAnalyzableActions(op.AllowActions)
			fate.BlockingLayer = "Layer 3 (SCP)"
			fate.BlockingReason = fmt.Sprintf("SCP restricts to [%s] only", strings.Join(explicit, ", "))
			return fate
		}
	}

	// Layer 6: permission boundary with explicit (non-wildcard) allow list.
	for _, r := range g.config.Roles {
		if r.HasBoundary && len(r.BoundaryActions) > 0 && !HasWildcardActions(r.BoundaryActions) {
			explicit := ExpandAnalyzableActions(r.BoundaryActions)
			fate.BlockingLayer = "Layer 6 (permission boundary)"
			fate.BlockingReason = fmt.Sprintf("permission boundary restricts to [%s] only", strings.Join(explicit, ", "))
			return fate
		}
	}
	for _, u := range g.config.Users {
		if u.HasBoundary && len(u.BoundaryActions) > 0 && !HasWildcardActions(u.BoundaryActions) {
			explicit := ExpandAnalyzableActions(u.BoundaryActions)
			fate.BlockingLayer = "Layer 6 (permission boundary)"
			fate.BlockingReason = fmt.Sprintf("permission boundary restricts to [%s] only", strings.Join(explicit, ", "))
			return fate
		}
	}

	fate.EffectivelyAllow = true
	return fate
}

// addWildcardLayer appends a layer label to wildcardLayers (no duplicates).
func (g *Generator) addWildcardLayer(label string) {
	for _, l := range g.wildcardLayers {
		if l == label {
			return
		}
	}
	g.wildcardLayers = append(g.wildcardLayers, label)
}

func Generate(config *ir.Config, sourceFile, outputFile string) error {
	return NewGenerator(config, sourceFile).GenerateToFile(outputFile)
}

func GenerateToWriter(config *ir.Config, sourceFile string, w io.Writer) error {
	return NewGenerator(config, sourceFile).GenerateToWriter(w)
}
