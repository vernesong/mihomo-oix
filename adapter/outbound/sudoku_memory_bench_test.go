package outbound

import "testing"

var benchmarkSudoku *Sudoku

func BenchmarkNewSudoku(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		node, err := NewSudoku(SudokuOption{Name: "benchmark", Server: "127.0.0.1", Port: 443, Key: "benchmark-key"})
		if err != nil {
			b.Fatal(err)
		}
		benchmarkSudoku = node
		_ = node.Close()
	}
}
