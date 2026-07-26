package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	pid := os.Args[1]

	mapsData, _ := os.ReadFile("/proc/" + pid + "/maps")
	maps := string(mapsData)

	type seg struct{ start, end uintptr }
	var segs []seg
	for _, line := range strings.Split(maps, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if !strings.Contains(fields[1], "rw") {
			continue
		}
		addrs := strings.Split(fields[0], "-")
		if len(addrs) != 2 {
			continue
		}
		var s, e uintptr
		fmt.Sscanf(addrs[0], "%x", &s)
		fmt.Sscanf(addrs[1], "%x", &e)
		size := e - s
		if size > 100*1024 && size < 50*1024*1024 {
			segs = append(segs, seg{s, e})
		}
	}
	fmt.Printf("Segments: %d\n", len(segs))

	// auth_key_id = SHA1(auth_key)[:8]
	// 从1163B消息确认: auth_key_id = 8c01b731e516801b
	targetID, _ := hex.DecodeString("8c01b731e516801b")
	fmt.Printf("target auth_key_id: %s\n", hex.EncodeToString(targetID))

	f, err := os.Open("/proc/" + pid + "/mem")
	if err != nil {
		fmt.Println("open err:", err)
		return
	}
	defer f.Close()

	buf := make([]byte, 4*1024*1024)
	found16 := 0
	found32 := 0
	found256 := 0
	checked := 0

	for _, s := range segs {
		offset := s.start
		for offset < s.end {
			readSize := uint64(len(buf))
			remaining := uint64(s.end - offset)
			if readSize > remaining {
				readSize = remaining
			}
			_, err := f.ReadAt(buf[:readSize], int64(offset))
			if err != nil {
				break
			}
			data := buf[:readSize]

			// 搜索16B块: SHA1(candidate)[:8] == auth_key_id
			for i := 0; i <= len(data)-16; i++ {
				block := data[i : i+16]
				// 快速过滤: 跳过全0或低entropy
				nonZero := 0
				for _, b := range block {
					if b != 0 {
						nonZero++
					}
				}
				if nonZero < 14 {
					continue
				}
				checked++

				hash := sha1.Sum(block)
				if hash[0] == targetID[0] && hash[1] == targetID[1] &&
					hash[2] == targetID[2] && hash[3] == targetID[3] &&
					hash[4] == targetID[4] && hash[5] == targetID[5] &&
					hash[6] == targetID[6] && hash[7] == targetID[7] {
					absAddr := offset + uintptr(i)
					fmt.Printf("\n=== 16B MATCH at 0x%x ===\n", absAddr)
					fmt.Printf("  key: %s\n", hex.EncodeToString(block))
					fmt.Printf("  SHA1: %s\n", hex.EncodeToString(hash[:]))
					found16++
					if found16 >= 5 {
						return
					}
				}
			}

			// 也搜索32B块
			for i := 0; i <= len(data)-32; i++ {
				block := data[i : i+32]
				nonZero := 0
				for _, b := range block {
					if b != 0 {
						nonZero++
					}
				}
				if nonZero < 28 {
					continue
				}

				hash := sha1.Sum(block)
				if hash[0] == targetID[0] && hash[1] == targetID[1] &&
					hash[2] == targetID[2] && hash[3] == targetID[3] &&
					hash[4] == targetID[4] && hash[5] == targetID[5] &&
					hash[6] == targetID[6] && hash[7] == targetID[7] {
					absAddr := offset + uintptr(i)
					fmt.Printf("\n=== 32B MATCH at 0x%x ===\n", absAddr)
					fmt.Printf("  key: %s\n", hex.EncodeToString(block))
					fmt.Printf("  SHA1: %s\n", hex.EncodeToString(hash[:]))
					found32++
					if found32 >= 5 {
						return
					}
				}
			}

			// 也搜索256B块(MTProto标准auth_key长度)
			for i := 0; i <= len(data)-256; i++ {
				block := data[i : i+256]
				nonZero := 0
				for _, b := range block {
					if b != 0 {
						nonZero++
					}
				}
				if nonZero < 240 {
					continue
				}

				hash := sha1.Sum(block)
				if hash[0] == targetID[0] && hash[1] == targetID[1] &&
					hash[2] == targetID[2] && hash[3] == targetID[3] &&
					hash[4] == targetID[4] && hash[5] == targetID[5] &&
					hash[6] == targetID[6] && hash[7] == targetID[7] {
					absAddr := offset + uintptr(i)
					fmt.Printf("\n=== 256B MATCH at 0x%x ===\n", absAddr)
					fmt.Printf("  key: %s\n", hex.EncodeToString(block[:64]))
					fmt.Printf("  SHA1: %s\n", hex.EncodeToString(hash[:]))
					found256++
					if found256 >= 5 {
						return
					}
				}
			}

			offset += uintptr(readSize)
		}
	}

	fmt.Printf("\nchecked=%d found16=%d found32=%d found256=%d\n", checked, found16, found32, found256)
}
