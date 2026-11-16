//go:build linux

package main

import (
	"strconv"
	"strings"
)

// vt is a small terminal emulator: enough of the escape sequences a
// full-screen program uses to draw (cursor moves, erase, insert and delete,
// repeat) to know what is on the screen, because the TUI's renderer redraws
// only the cells that changed, so the byte stream alone does not contain whole
// lines. It ignores colours and modes.
type vt struct {
	rows, cols int
	top, bot   int // the scroll region, inclusive
	cells      [][]rune
	r, c       int
	saved      [2]int
	last       rune
	state      int // 0 text, 1 after ESC, 2 in CSI, 3 in OSC, 4 ESC inside OSC
	params     []byte
	utf        []byte
}

func newVT(rows, cols int) *vt {
	v := &vt{}
	v.resize(rows, cols)
	return v
}

func (v *vt) resize(rows, cols int) {
	v.rows, v.cols = rows, cols
	v.top, v.bot = 0, rows-1
	v.cells = make([][]rune, rows)
	for i := range v.cells {
		v.cells[i] = blankRow(cols)
	}
	v.r, v.c = 0, 0
}

func blankRow(n int) []rune {
	row := make([]rune, n)
	for i := range row {
		row[i] = ' '
	}
	return row
}

// String is the screen, one line per row, trailing blanks removed.
func (v *vt) String() string {
	lines := make([]string, v.rows)
	for i, row := range v.cells {
		lines[i] = strings.TrimRight(string(row), " ")
	}
	return strings.Join(lines, "\n")
}

func (v *vt) scrollUp() {
	copy(v.cells[v.top:v.bot], v.cells[v.top+1:v.bot+1])
	v.cells[v.bot] = blankRow(v.cols)
}

func (v *vt) scrollDown() {
	copy(v.cells[v.top+1:v.bot+1], v.cells[v.top:v.bot])
	v.cells[v.top] = blankRow(v.cols)
}

func (v *vt) put(r rune) {
	if v.c >= v.cols {
		v.c = 0
		v.nl()
	}
	v.cells[v.r][v.c] = r
	v.c++
	v.last = r
}

func (v *vt) nl() {
	switch {
	case v.r == v.bot:
		v.scrollUp()
	case v.r < v.rows-1:
		v.r++
	}
}

func (v *vt) Write(b []byte) {
	for _, x := range b {
		v.feed(x)
	}
}

func (v *vt) feed(b byte) {
	switch v.state {
	case 1:
		switch b {
		case '[':
			v.state, v.params = 2, v.params[:0]
		case ']':
			v.state = 3
		case '7':
			v.saved, v.state = [2]int{v.r, v.c}, 0
		case '8':
			v.r, v.c, v.state = v.saved[0], v.saved[1], 0
		case 'M':
			if v.r > 0 {
				v.r--
			}
			v.state = 0
		case '(', ')', '#':
			// a one-byte argument follows; swallow it as an escape of its own
			v.state = 5
		default:
			v.state = 0
		}
		return
	case 5:
		v.state = 0
		return
	case 2:
		if b >= 0x40 && b <= 0x7e {
			v.csi(b, string(v.params))
			v.state = 0
		} else {
			v.params = append(v.params, b)
		}
		return
	case 3:
		switch b {
		case 0x07:
			v.state = 0
		case 0x1b:
			v.state = 4
		}
		return
	case 4:
		v.state = 0 // ESC \ ends the string
		return
	}
	switch {
	case b == 0x1b:
		v.state = 1
	case b == '\r':
		v.c = 0
	case b == '\n':
		v.nl()
	case b == '\b':
		if v.c > 0 {
			v.c--
		}
	case b == '\t':
		v.c = min((v.c/8+1)*8, v.cols-1)
	case b < 0x20:
	case b < 0x80:
		v.put(rune(b))
	default:
		v.utf = append(v.utf, b)
		if r := []rune(string(v.utf)); len(r) == 1 && r[0] != 0xfffd {
			v.utf = v.utf[:0]
			v.put(r[0])
		} else if len(v.utf) >= 4 {
			v.utf = v.utf[:0]
		}
	}
}

func nums(p string, def int) []int {
	p = strings.TrimLeft(p, "?>=<")
	if p == "" {
		return []int{def}
	}
	var out []int
	for _, f := range strings.Split(p, ";") {
		n, err := strconv.Atoi(f)
		if err != nil || n == 0 && def != 0 && false {
			n = def
		}
		out = append(out, n)
	}
	return out
}

func (v *vt) csi(final byte, params string) {
	if strings.HasPrefix(params, "?") || strings.HasPrefix(params, ">") || strings.HasPrefix(params, "<") || strings.HasPrefix(params, "=") {
		return // modes and queries
	}
	n := nums(params, 1)
	one := func() int {
		if n[0] < 1 {
			return 1
		}
		return n[0]
	}
	clampR := func() { v.r = min(max(v.r, 0), v.rows-1) }
	clampC := func() { v.c = min(max(v.c, 0), v.cols-1) }
	switch final {
	case 'H', 'f':
		row, col := 1, 1
		if len(n) > 0 && n[0] > 0 {
			row = n[0]
		}
		if len(n) > 1 && n[1] > 0 {
			col = n[1]
		}
		v.r, v.c = row-1, col-1
		clampR()
		clampC()
	case 'A':
		v.r -= one()
		clampR()
	case 'B', 'e':
		v.r += one()
		clampR()
	case 'C', 'a':
		v.c += one()
		clampC()
	case 'D':
		v.c -= one()
		clampC()
	case 'E':
		v.r, v.c = v.r+one(), 0
		clampR()
	case 'F':
		v.r, v.c = v.r-one(), 0
		clampR()
	case 'G', '`':
		v.c = one() - 1
		clampC()
	case 'd':
		v.r = one() - 1
		clampR()
	case 'K':
		mode := 0
		if params != "" {
			mode = n[0]
		}
		switch mode {
		case 0:
			for i := v.c; i < v.cols; i++ {
				v.cells[v.r][i] = ' '
			}
		case 1:
			for i := 0; i <= v.c && i < v.cols; i++ {
				v.cells[v.r][i] = ' '
			}
		case 2:
			v.cells[v.r] = blankRow(v.cols)
		}
	case 'J':
		mode := 0
		if params != "" {
			mode = n[0]
		}
		switch mode {
		case 0:
			for i := v.c; i < v.cols; i++ {
				v.cells[v.r][i] = ' '
			}
			for r := v.r + 1; r < v.rows; r++ {
				v.cells[r] = blankRow(v.cols)
			}
		case 1:
			for r := 0; r < v.r; r++ {
				v.cells[r] = blankRow(v.cols)
			}
			for i := 0; i <= v.c && i < v.cols; i++ {
				v.cells[v.r][i] = ' '
			}
		default:
			for r := range v.cells {
				v.cells[r] = blankRow(v.cols)
			}
		}
	case 'X':
		for i := v.c; i < v.c+one() && i < v.cols; i++ {
			v.cells[v.r][i] = ' '
		}
	case 'P':
		k := min(one(), v.cols-v.c)
		row := v.cells[v.r]
		copy(row[v.c:], row[v.c+k:])
		for i := v.cols - k; i < v.cols; i++ {
			row[i] = ' '
		}
	case '@':
		k := min(one(), v.cols-v.c)
		row := v.cells[v.r]
		copy(row[v.c+k:], row[v.c:v.cols-k])
		for i := v.c; i < v.c+k; i++ {
			row[i] = ' '
		}
	case 'L':
		if v.r >= v.top && v.r <= v.bot {
			for k := 0; k < one(); k++ {
				copy(v.cells[v.r+1:v.bot+1], v.cells[v.r:v.bot])
				v.cells[v.r] = blankRow(v.cols)
			}
		}
	case 'M':
		if v.r >= v.top && v.r <= v.bot {
			for k := 0; k < one(); k++ {
				copy(v.cells[v.r:v.bot], v.cells[v.r+1:v.bot+1])
				v.cells[v.bot] = blankRow(v.cols)
			}
		}
	case 'S':
		for k := 0; k < one(); k++ {
			v.scrollUp()
		}
	case 'T':
		for k := 0; k < one(); k++ {
			v.scrollDown()
		}
	case 'r':
		top, bot := 1, v.rows
		if params != "" {
			if len(n) > 0 && n[0] > 0 {
				top = n[0]
			}
			if len(n) > 1 && n[1] > 0 {
				bot = n[1]
			}
		}
		if top < bot && bot <= v.rows {
			v.top, v.bot, v.r, v.c = top-1, bot-1, 0, 0
		}
	case 'b':
		for k := 0; k < one(); k++ {
			v.put(v.last)
		}
	case 's':
		v.saved = [2]int{v.r, v.c}
	case 'u':
		v.r, v.c = v.saved[0], v.saved[1]
	}
}
