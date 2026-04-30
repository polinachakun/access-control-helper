package ir

import "access-control-helper/internal/resolver"

type ResourceNav struct {
	res *resolver.ResolvedResource
}

type BlockNav struct {
	block *resolver.ResolvedBlock
	found bool
}

func NavResource(res *resolver.ResolvedResource) *ResourceNav {
	return &ResourceNav{res: res}
}

func (rn *ResourceNav) Block(blockType string) *BlockNav {
	if rn.res == nil {
		return &BlockNav{}
	}
	blocks, ok := rn.res.Blocks[blockType]
	if !ok || len(blocks) == 0 {
		return &BlockNav{}
	}
	b := blocks[0]
	return &BlockNav{block: &b, found: true}
}

func (rn *ResourceNav) Blocks(blockType string) []*BlockNav {
	if rn.res == nil {
		return nil
	}
	raw, ok := rn.res.Blocks[blockType]
	if !ok {
		return nil
	}
	result := make([]*BlockNav, len(raw))
	for i := range raw {
		b := raw[i]
		result[i] = &BlockNav{block: &b, found: true}
	}
	return result
}

func (bn *BlockNav) Block(blockType string) *BlockNav {
	if !bn.found || bn.block == nil {
		return &BlockNav{}
	}
	children, ok := bn.block.Blocks[blockType]
	if !ok || len(children) == 0 {
		return &BlockNav{}
	}
	c := children[0]
	return &BlockNav{block: &c, found: true}
}

func (bn *BlockNav) Blocks(blockType string) []*BlockNav {
	if !bn.found || bn.block == nil {
		return nil
	}
	raw, ok := bn.block.Blocks[blockType]
	if !ok {
		return nil
	}
	result := make([]*BlockNav, len(raw))
	for i := range raw {
		b := raw[i]
		result[i] = &BlockNav{block: &b, found: true}
	}
	return result
}

func (bn *BlockNav) Str(attrName string) string {
	if !bn.found || bn.block == nil {
		return ""
	}
	v, ok := bn.block.Attributes[attrName]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func (bn *BlockNav) Found() bool {
	return bn.found
}
