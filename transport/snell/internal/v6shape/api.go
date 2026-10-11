package v6shape

// Profile is immutable after construction and may be shared by both directions.
func (p *Profile) SaltBlockLen() int { return p.saltBlockLen }

func (p *Profile) EncodeSalt(salt, block []byte) {
	p.fillPadding(0xffffffff, block)
	p.writeSaltBlock(salt, block)
}

func (p *Profile) DecodeSalt(block []byte) [16]byte { return p.extractSalt(block) }
func (p *Profile) PrefixLen(seq uint32) int         { return p.recordPrefixLen(seq) }
func (p *Profile) Fill(seq uint32, dst []byte)      { p.fillPadding(seq, dst) }

func (p *Profile) PaddingLen(seq uint32, payloadLen int, first bool) int {
	saltBlock, saltPrefix := 0, 0
	if first {
		saltBlock, saltPrefix = p.saltBlockLen, p.saltBlockLen-saltLen
	}
	return p.paddingLen(seq, payloadLen, p.recordPrefixLen(seq), saltPrefix, saltBlock)
}

// Mixing swaps the same positions in either direction, so it is its own inverse.
func (p *Profile) Mix(seq uint32, padding, payload []byte) {
	p.mixPaddingPayload(seq, padding, payload)
}

// ChunkState is local to one writer. The caller serializes access.
type ChunkState struct {
	size int
	last int64
}

func (p *Profile) PayloadLimit(seq uint32, now int64, state *ChunkState) int {
	if state.last == 0 || now-state.last > int64(p.idleResetSec) || state.size == 0 {
		state.size = p.chunkInitial
	}
	limit := p.chunkPayloadLimit(seq, state.size)
	if seq == 0 {
		limit = min(limit, p.firstRecordCap)
	}
	state.size = p.nextChunkSize(state.size)
	state.last = now
	return max(1, min(limit, 0xffff))
}
