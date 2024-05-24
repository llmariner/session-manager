package flushwriter

import (
	"io"
	"net/http"
)

// W is a Writer that flushes whenever write happens.
// This is used to avoid buffering in http.ResponseWriter.
//
// The copy is copied from
// https://stackoverflow.com/questions/19292113/not-buffered-http-responsewritter-in-golang
type W struct {
	w io.Writer
	f http.Flusher
}

// New returns a new W.
func New(w io.Writer) *W {
	fw := &W{
		w: w,
	}
	if f, ok := w.(http.Flusher); ok {
		fw.f = f
	}
	return fw
}

// Write writes and flushes.
func (fw *W) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return
}
