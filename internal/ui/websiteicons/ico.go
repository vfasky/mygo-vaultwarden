// SPDX-License-Identifier: GPL-3.0-only
package websiteicons

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"sort"
)

// Vaultwarden's icon.png route may return an ICO file. Support PNG frames and
// conventional uncompressed Windows DIB frames, including their transparency.
func decodeICO(data []byte) (image.Image, error) {
	invalid := fmt.Errorf("unsupported icon")
	count := int(binary.LittleEndian.Uint16(data[4:6]))
	if count < 1 || count > 256 || len(data) < 6+16*count {
		return nil, invalid
	}
	type frame struct {
		size int
		data []byte
	}
	var frames []frame
	for i := 0; i < count; i++ {
		e := data[6+i*16 : 6+(i+1)*16]
		w, h := int(e[0]), int(e[1])
		if w == 0 {
			w = 256
		}
		if h == 0 {
			h = 256
		}
		n, offset := uint64(binary.LittleEndian.Uint32(e[8:12])), uint64(binary.LittleEndian.Uint32(e[12:16]))
		if n == 0 || offset < uint64(6+16*count) || offset+n > uint64(len(data)) {
			continue
		}
		frames = append(frames, frame{w * h, data[offset : offset+n]})
	}
	sort.SliceStable(frames, func(i, j int) bool { return frames[i].size > frames[j].size })
	for _, frame := range frames {
		var img image.Image
		var err error
		if bytes.HasPrefix(frame.data, []byte("\x89PNG\r\n\x1a\n")) {
			img, err = decode(frame.data)
		} else {
			img, err = decodeDIB(frame.data)
		}
		if err == nil {
			return img, nil
		}
	}
	return nil, invalid
}

func decodeDIB(data []byte) (image.Image, error) {
	invalid := fmt.Errorf("unsupported icon bitmap")
	if len(data) < 40 {
		return nil, invalid
	}
	header := int(binary.LittleEndian.Uint32(data[:4]))
	w, doubledHeight := int(int32(binary.LittleEndian.Uint32(data[4:8]))), int(int32(binary.LittleEndian.Uint32(data[8:12])))
	bpp := int(binary.LittleEndian.Uint16(data[14:16]))
	if header < 40 || header > len(data) || w < 1 || w > 256 || doubledHeight < 2 || doubledHeight > 512 || doubledHeight%2 != 0 || binary.LittleEndian.Uint16(data[12:14]) != 1 || binary.LittleEndian.Uint32(data[16:20]) != 0 {
		return nil, invalid
	}
	if bpp != 1 && bpp != 4 && bpp != 8 && bpp != 24 && bpp != 32 {
		return nil, invalid
	}
	h := doubledHeight / 2
	paletteSize := 0
	if bpp <= 8 {
		paletteSize = int(binary.LittleEndian.Uint32(data[32:36]))
		if paletteSize == 0 {
			paletteSize = 1 << bpp
		}
		if paletteSize > 1<<bpp {
			return nil, invalid
		}
	}
	start := header + paletteSize*4
	stride, maskStride := ((w*bpp+31)/32)*4, ((w+31)/32)*4
	end := start + stride*h
	if end > len(data) {
		return nil, invalid
	}
	hasMask := end+maskStride*h <= len(data)
	if !hasMask && bpp != 32 {
		return nil, invalid
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	hasAlpha := false
	for y := 0; y < h; y++ {
		row := data[start+(h-1-y)*stride : start+(h-y)*stride]
		for x := 0; x < w; x++ {
			c := color.NRGBA{A: 255}
			if bpp <= 8 {
				bit := x * bpp
				index := int(row[bit/8]>>(8-bpp-bit%8)) & ((1 << bpp) - 1)
				if index >= paletteSize {
					return nil, invalid
				}
				p := data[header+index*4 : header+(index+1)*4]
				c.R, c.G, c.B = p[2], p[1], p[0]
			} else {
				p := row[x*(bpp/8):]
				c.R, c.G, c.B = p[2], p[1], p[0]
				if bpp == 32 {
					c.A = p[3]
					hasAlpha = hasAlpha || c.A != 0
				}
			}
			img.SetNRGBA(x, y, c)
		}
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			a := img.PixOffset(x, y) + 3
			if bpp == 32 && !hasAlpha {
				img.Pix[a] = 255
			}
			if hasMask && data[end+(h-1-y)*maskStride+x/8]&(0x80>>uint(x%8)) != 0 {
				img.Pix[a] = 0
			}
		}
	}
	return img, nil
}
