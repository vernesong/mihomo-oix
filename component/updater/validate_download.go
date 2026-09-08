package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

const maxUnpackedBytes int64 = 256 << 20

func validateVersion(data []byte) error {
	value := strings.TrimSpace(string(data))
	if value == "" || len(value) > 128 {
		return errors.New("invalid version response")
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return errors.New("invalid version response")
		}
	}
	return nil
}

func validateArchivePath(name string) error {
	if name == "" || strings.ContainsAny(name, "\\:\x00") || path.IsAbs(name) {
		return errors.New("invalid archive path")
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return errors.New("archive path escapes destination")
		}
	}
	return nil
}

func validateGzipName(name string) error {
	if name == "" {
		return nil
	}
	if err := validateArchivePath(name); err != nil {
		return err
	}
	if name == "." || path.Base(name) != name {
		return errors.New("gzip filename must be a basename")
	}
	return nil
}

func validateCoreArchive(data []byte, filename string, targetName ...string) error {
	switch {
	case strings.HasSuffix(filename, ".zip"):
		if detectFileType(data) != typeZip {
			return errors.New("unexpected core archive format")
		}
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return err
		}
		if len(archive.File) == 0 || !archive.File[0].Mode().IsRegular() || archive.File[0].UncompressedSize64 == 0 {
			return errors.New("core ZIP target must be a non-empty regular file")
		}
		firstName := archive.File[0].FileInfo().Name()
		if err := validateGzipName(firstName); err != nil {
			return err
		}
		if len(targetName) > 0 && firstName != targetName[0] {
			return errors.New("core ZIP target filename mismatch")
		}
	case strings.HasSuffix(filename, ".gz"):
		if detectFileType(data) != typeTarGzip {
			return errors.New("unexpected core archive format")
		}
	default:
		return errors.New("unknown core archive format")
	}
	return validateArchive(data, false)
}

func validateArchive(data []byte, tarGzip bool) error {
	remaining := maxUnpackedBytes
	check := func(reader io.Reader) (int64, error) {
		n, err := io.Copy(io.Discard, io.LimitReader(reader, remaining+1))
		remaining -= n
		if remaining < 0 {
			return n, fmt.Errorf("archive exceeds %d unpacked bytes", maxUnpackedBytes)
		}
		return n, err
	}
	switch detectFileType(data) {
	case typeZip:
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return err
		}
		hasContent := false
		for _, entry := range archive.File {
			if err := validateArchivePath(entry.Name); err != nil {
				return err
			}
			if entry.Mode().IsRegular() && path.Clean(entry.Name) == "." {
				return errors.New("invalid archive filename")
			}
			if !entry.Mode().IsRegular() && !entry.FileInfo().IsDir() {
				return errors.New("unsupported archive entry type")
			}
			reader, err := entry.Open()
			if err != nil {
				return err
			}
			n, err := check(reader)
			closeErr := reader.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if entry.Mode().IsRegular() && n > 0 {
				hasContent = true
			}
		}
		if !hasContent {
			return errors.New("archive has no non-empty regular file")
		}
		return nil
	case typeTarGzip:
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return err
		}
		defer reader.Close()
		if tarGzip {
			unpacked := &io.LimitedReader{R: reader, N: remaining + 1}
			archive := tar.NewReader(unpacked)
			hasContent := false
			for {
				header, err := archive.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					return err
				}
				if err := validateArchivePath(header.Name); err != nil {
					return err
				}
				switch header.Typeflag {
				case tar.TypeReg, tar.TypeRegA:
					if path.Clean(header.Name) == "." {
						return errors.New("invalid archive filename")
					}
				case tar.TypeDir:
				default:
					return errors.New("unsupported archive entry type")
				}
				n, err := io.Copy(io.Discard, archive)
				if err != nil {
					return err
				}
				if (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) && n > 0 {
					hasContent = true
				}
			}
			if !hasContent {
				return errors.New("archive has no non-empty regular file")
			}
			if _, err := io.Copy(io.Discard, unpacked); err != nil {
				return err
			}
			if unpacked.N <= 0 {
				return errors.New("archive exceeds unpacked size limit")
			}
			return nil
		}
		if err := validateGzipName(reader.Header.Name); err != nil {
			return err
		}
		n, err := check(reader)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("empty gzip archive")
		}
		return nil
	default:
		return errors.New("unsupported archive response")
	}
}
