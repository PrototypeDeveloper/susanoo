package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"hash/fnv"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"
)

// 索引（2m-3）。日付ごとのファイル（<prefix>-YYYYMMDD.jsonl）の横に <prefix>-YYYYMMDD.idx を置く。索引は、行のまとまり
// （ブロック。blockLines 行か blockBytes バイトまで）ごとに 1 行の JSON で、ファイルの中の位置と長さ、行の時刻の範囲、
// 行に付けた印（種類、端末など）のブルームフィルターを持つ。検索は、条件に合い得ないブロックを読まない。
// 索引のない部分（書いている途中のブロック、異常終了で索引を書けなかったブロック、索引を入れる前のファイル）は、
// これまでどおりすべて読む。索引は読む量を減らすためだけのもので、行が条件に合うかは match で確かめる。

const (
	blockLines  = 1000
	blockBytes  = 512 << 10
	bloomBits   = 8192
	bloomHashes = 4
)

// Indexer は、保存する値から、時刻（UNIX 時間のミリ秒。分からなければ 0）と印を取り出す。
type Indexer func(v any) (t int64, tags []string)

// Filter は検索の条件のうち、索引で絞り込めるもの。
type Filter struct {
	Since, Until time.Time  // 行の時刻の範囲（ゼロなら制限しない）。Since はファイルの日付の絞り込みにも使う
	Tags         [][]string // 印の条件。外側の各組の、どれか 1 つの印を持つ行だけ（組どうしは「かつ」）
}

// blockIndex は索引の 1 行。
type blockIndex struct {
	Off   int64  `json:"off"`
	Len   int64  `json:"len"`
	Min   int64  `json:"min"`
	Max   int64  `json:"max"`
	Bloom []byte `json:"bloom"`
}

// block は書いている途中のブロック。
type block struct {
	off, size int64
	lines     int
	min, max  int64
	bloom     [bloomBits / 8]byte
}

func bloomPositions(tag string) [bloomHashes]uint32 {
	h := fnv.New64a()
	h.Write([]byte(tag))
	sum := h.Sum64()
	h1, h2 := uint32(sum), uint32(sum>>32)|1
	var out [bloomHashes]uint32
	for i := range out {
		out[i] = (h1 + uint32(i)*h2) % bloomBits
	}
	return out
}

func bloomAdd(b []byte, tag string) {
	for _, p := range bloomPositions(tag) {
		b[p/8] |= 1 << (p % 8)
	}
}

func bloomHas(b []byte, tag string) bool {
	if len(b) != bloomBits/8 {
		return true // 形の違う索引では絞り込まない
	}
	for _, p := range bloomPositions(tag) {
		if b[p/8]&(1<<(p%8)) == 0 {
			return false
		}
	}
	return true
}

// indexName は日付のファイルの索引のファイルの名前を返す。
func indexName(path string) string { return strings.TrimSuffix(path, ".jsonl") + ".idx" }

// note は、ファイルの off から書いた 1 行（n バイト、時刻 t、印 tags）を今のブロックに加え、ブロックが大きくなったら索引に書く。s.mu を持って呼ぶ。
func (s *JSONL) note(off int64, n int, t int64, tags []string) {
	b := s.blk
	if b == nil {
		b = &block{off: off, min: t, max: t}
		s.blk = b
	}
	b.size += int64(n)
	b.lines++
	b.min, b.max = min(b.min, t), max(b.max, t)
	for _, tag := range tags {
		bloomAdd(b.bloom[:], tag)
	}
	if b.lines >= blockLines || b.size >= blockBytes {
		s.flushBlock()
	}
}

// flushBlock は今のブロックを索引に書く。索引は読む量を減らすためだけのものなので、書けなくても保存は続ける。s.mu を持って呼ぶ。
func (s *JSONL) flushBlock() {
	b := s.blk
	s.blk = nil
	if b == nil || s.day == "" {
		return
	}
	line, err := json.Marshal(blockIndex{Off: b.off, Len: b.size, Min: b.min, Max: b.max, Bloom: b.bloom[:]})
	if err != nil {
		return
	}
	if s.idx == nil {
		f, err := os.OpenFile(indexName(s.dirPath(s.fileName(s.day))), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return
		}
		s.idx = f
	}
	s.idx.Write(append(line, '\n'))
}

// closeIndex は今のブロックを書いて、索引のファイルを閉じる。s.mu を持って呼ぶ。
func (s *JSONL) closeIndex() {
	s.flushBlock()
	if s.idx != nil {
		s.idx.Close()
		s.idx = nil
	}
}

// readIndex は、大きさ size のファイル path の索引を読み、位置の順に並べて返す。壊れた行と、ファイルの外を指す行は使わない。
// ブロックが重なっていたら（索引が信用できない）、nil を返してファイルをすべて読ませる。
func readIndex(path string, size int64) []blockIndex {
	f, err := os.Open(indexName(path))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []blockIndex
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var b blockIndex
		if json.Unmarshal(sc.Bytes(), &b) != nil || b.Off < 0 || b.Len <= 0 || b.Off+b.Len > size {
			continue
		}
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b blockIndex) int { return int(a.Off - b.Off) })
	for i := 1; i < len(out); i++ {
		if out[i].Off < out[i-1].Off+out[i-1].Len {
			return nil
		}
	}
	return out
}

// matches は、ブロックに条件に合う行があり得るかを返す。
func (b blockIndex) matches(f Filter) bool {
	if !f.Since.IsZero() && b.Max < f.Since.UnixMilli() {
		return false
	}
	if !f.Until.IsZero() && b.Min > f.Until.UnixMilli() {
		return false
	}
	for _, group := range f.Tags {
		if !slices.ContainsFunc(group, func(tag string) bool { return bloomHas(b.Bloom, tag) }) {
			return false
		}
	}
	return true
}

// region はファイルの中の読む範囲。
type region struct{ off, size int64 }

// matchFile はファイルのうち match が真を返す行を、新しいものから n 件まで、古い順に返す。索引で、条件に合い得ないブロックは読まない。
func (s *JSONL) matchFile(path string, flt Filter, match func([]byte) bool, n int) ([][]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // 古いファイルを消した後
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	var regions []region
	pos := int64(0)
	for _, b := range readIndex(path, size) {
		if b.Off > pos {
			regions = append(regions, region{pos, b.Off - pos}) // 索引のない部分
		}
		if b.matches(flt) {
			regions = append(regions, region{b.Off, b.Len})
		}
		pos = b.Off + b.Len
	}
	if pos < size {
		regions = append(regions, region{pos, size - pos})
	}
	var out [][]byte
	for i := len(regions) - 1; i >= 0 && len(out) < n; i-- {
		found := s.scan(f, regions[i], match, n-len(out))
		out = append(found, out...)
	}
	return out, nil
}

// scan は範囲 r の行のうち match が真を返すものを、新しいものから n 件まで、古い順に返す。改行で終わらない行（追記の途中）は読まない。
func (s *JSONL) scan(f *os.File, r region, match func([]byte) bool, n int) [][]byte {
	s.scanned.Add(r.size)
	br := bufio.NewReaderSize(io.NewSectionReader(f, r.off, r.size), 64<<10)
	var found [][]byte
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return found // 終わり、または追記の途中の行
		}
		line = line[:len(line)-1]
		if match(line) {
			found = append(found, line)
			if len(found) > n {
				found = found[1:]
			}
		}
	}
}
