package trie

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

func (ss *DomainSet) WriteBin(w io.Writer) (err error) {
	// version
	_, err = w.Write([]byte{1})
	if err != nil {
		return err
	}

	// leaves
	err = binary.Write(w, binary.BigEndian, int64(len(ss.leaves)))
	if err != nil {
		return err
	}
	for _, d := range ss.leaves {
		err = binary.Write(w, binary.BigEndian, d)
		if err != nil {
			return err
		}
	}

	// labelBitmap
	err = binary.Write(w, binary.BigEndian, int64(len(ss.labelBitmap)))
	if err != nil {
		return err
	}
	for _, d := range ss.labelBitmap {
		err = binary.Write(w, binary.BigEndian, d)
		if err != nil {
			return err
		}
	}

	// labels
	err = binary.Write(w, binary.BigEndian, int64(len(ss.labels)))
	if err != nil {
		return err
	}
	_, err = w.Write(ss.labels)
	if err != nil {
		return err
	}

	return nil
}

func ReadDomainSetBin(r io.Reader) (ds *DomainSet, err error) {
	// version
	version := make([]byte, 1)
	_, err = io.ReadFull(r, version)
	if err != nil {
		return nil, err
	}
	if version[0] != 1 {
		return nil, errors.New("version is invalid")
	}

	ds = &DomainSet{}
	if ds.leaves, err = readDomainBitmap(r); err != nil {
		return nil, err
	}
	if ds.labelBitmap, err = readDomainBitmap(r); err != nil {
		return nil, err
	}

	var length int64
	if err = binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	// Rank/select indexes use int32 positions in the 2*n+1-bit tree.
	if length < 1 || length > (math.MaxInt32-1)/2 {
		return nil, errors.New("length is invalid")
	}
	ds.labels, err = io.ReadAll(io.LimitReader(r, length))
	if err != nil {
		return nil, err
	}
	if int64(len(ds.labels)) != length {
		return nil, io.ErrUnexpectedEOF
	}
	if !ds.validBinaryTree() {
		return nil, errors.New("invalid domain set structure")
	}
	ds.init()
	return ds, nil
}

// Grow only as complete words arrive; a short file must not allocate according
// to an untrusted length before its payload has been read.
func readDomainBitmap(r io.Reader) ([]uint64, error) {
	var length int64
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length < 1 || length > math.MaxInt32/64+1 {
		return nil, errors.New("length is invalid")
	}
	words := make([]uint64, 0, min(length, 1024))
	for range length {
		var word uint64
		if err := binary.Read(r, binary.BigEndian, &word); err != nil {
			return nil, err
		}
		words = append(words, word)
	}
	return words, nil
}

func (ds *DomainSet) validBinaryTree() bool {
	nodes := len(ds.labels) + 1
	bits := 2*nodes - 1
	if len(ds.leaves) != (nodes+63)/64 || len(ds.labelBitmap) != (bits+63)/64 {
		return false
	}
	if nodes%64 != 0 && ds.leaves[len(ds.leaves)-1]>>uint(nodes%64) != 0 {
		return false
	}
	if bits%64 != 0 && ds.labelBitmap[len(ds.labelBitmap)-1]>>uint(bits%64) != 0 {
		return false
	}
	// Each zero adds one child; each one finishes the next node in breadth-
	// first order. The queue must become empty only at the final delimiter.
	pending := 1
	for position := range bits {
		if getBit(ds.labelBitmap, position) == 0 {
			pending++
		} else {
			pending--
		}
		if pending == 0 && position != bits-1 {
			return false
		}
	}
	return pending == 0
}
