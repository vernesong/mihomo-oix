package provider

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// Bound decompression independently of the compressed HTTP response size.
const maxMrsBytes int64 = 256 << 20

var MrsMagicBytes = [4]byte{'M', 'R', 'S', 1} // MRSv1

func rulesMrsParse(buf []byte, strategy ruleStrategy) (ruleStrategy, error) {
	if _strategy, ok := strategy.(mrsRuleStrategy); ok {
		decoder, err := zstd.NewReader(bytes.NewReader(buf), zstd.WithDecoderMaxMemory(uint64(maxMrsBytes)))
		if err != nil {
			return nil, err
		}
		defer decoder.Close()
		reader := &io.LimitedReader{R: decoder, N: maxMrsBytes + 1}

		// header
		var header [4]byte
		_, err = io.ReadFull(reader, header[:])
		if err != nil {
			return nil, err
		}
		if header != MrsMagicBytes {
			return nil, fmt.Errorf("invalid MrsMagic bytes")
		}

		// behavior
		var _behavior [1]byte
		_, err = io.ReadFull(reader, _behavior[:])
		if err != nil {
			return nil, err
		}
		if _behavior[0] != strategy.Behavior().Byte() {
			return nil, fmt.Errorf("invalid behavior")
		}

		// count
		var count int64
		err = binary.Read(reader, binary.BigEndian, &count)
		if err != nil {
			return nil, err
		}

		if count < 1 || int64(int(count)) != count {
			return nil, errors.New("rule count is invalid")
		}

		// extra (reserved for future using)
		var length int64
		err = binary.Read(reader, binary.BigEndian, &length)
		if err != nil {
			return nil, err
		}
		if length < 0 {
			return nil, errors.New("length is invalid")
		}
		if length > 0 {
			_, err = io.CopyN(io.Discard, reader, length)
			if err != nil {
				return nil, err
			}
		}

		if err = _strategy.FromMrs(reader, int(count)); err != nil {
			return nil, err
		}
		// Finish the stream so checksum failures and oversized trailing data
		// cannot turn a partially validated candidate into a published rule set.
		if _, err = io.Copy(io.Discard, reader); err != nil {
			return nil, err
		}
		if reader.N <= 0 {
			return nil, errors.New("MRS exceeds decompressed size limit")
		}
		return strategy, nil
	} else {
		return nil, ErrInvalidFormat
	}
}
