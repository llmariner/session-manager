package proxy

import (
	"fmt"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
	"k8s.io/klog/v2"
)

// ConnObserver is the interface to receive updates on the connections.
type ConnObserver interface {
	// OnMarkDead is called when the client for the id is disconnected.
	OnMarkDead(id string)
}

// h2ConnPool is a collection of http2.ClientConns, keyed by name. The connection
// for each ID is used to proxy requests from the proxy to the agent.
//
// The h2ConnPool implements http2.ClientConnPool, which allows for a single
// http.Client to be used to communicate with multiple backend connections.
type h2ConnPool struct {
	t *http2.Transport
	m sync.RWMutex

	conns map[string][]*http2.ClientConn

	observer ConnObserver
}

// newH2ConnPool returns a new h2ConnPool, using the given http2.Transport as
// the transport for the client.
func newH2ConnPool(t *http2.Transport) *h2ConnPool {
	p := &h2ConnPool{
		t:     t,
		conns: make(map[string][]*http2.ClientConn),
	}
	t.ConnPool = p
	return p
}

// AddConn implements http2.ClientConnPool by adding the given net.Conn to the
// h2ConnPool with the given id.
//
// When a connection is added to the h2ConnPool, the net.Conn is used to
// instantiate a new http2.ClientConn that is placed in the
// map.
func (p *h2ConnPool) AddConn(conn net.Conn, id string) error {
	klog.Infof("adding connection; ID=%q; proto=HTTP", id)

	p.m.Lock()
	defer p.m.Unlock()

	// TODO: check if we already have a connection for this ID.
	if _, ok := p.conns[id]; ok {
		klog.Warningf("found existing connection; ID=%q", id)
	}

	c, err := p.t.NewClientConn(conn)
	if err != nil {
		return err
	}
	p.conns[id] = append(p.conns[id], c)

	return nil
}

// GetClientConn implements http2.ClientConnPool by fetching the appropriate
// http2.ClientConn from the map based on the target ID.
func (p *h2ConnPool) GetClientConn(r *http.Request, _ string) (*http2.ClientConn, error) {
	p.m.RLock()
	defer p.m.RUnlock()

	id := r.Host
	klog.Infof("fetching HTTP connection; ID=%q, URL=%s", id, r.URL)

	cs, ok := p.conns[id]
	if !ok {
		return nil, fmt.Errorf("tunnel: get client conn: client not found (ID=%q)", id)
	}

	for _, c := range cs {
		if c.CanTakeNewRequest() {
			return c, nil
		}
	}

	return nil, fmt.Errorf("tunnel: get client conn: client not connected (ID=%q)", id)
}

// MarkDead implements http2.ClientConnPool by marking the http2.ClientConn as
// inactive, closing the underlying http2.ClientConn.
func (p *h2ConnPool) MarkDead(c *http2.ClientConn) {
	p.m.Lock()
	defer p.m.Unlock()
	found := false
	for id, cps := range p.conns {
		if found {
			break
		}

		var newConns []*http2.ClientConn
		for _, cp := range cps {
			if cp != c {
				newConns = append(newConns, cp)
				continue
			}
			klog.Infof("marking connection dead; ID=%q", id)
			_ = cp.Close()
			found = true
			if p.observer != nil {
				p.observer.OnMarkDead(id)
			}
		}
		p.conns[id] = newConns
	}
	if !found {
		klog.Errorf("no connection found when marking dead")
	}
}

// hasConn returns true if the h2ConnPool has a connection for the given ID.
func (p *h2ConnPool) hasConn(id string) bool {
	p.m.RLock()
	defer p.m.RUnlock()
	_, ok := p.conns[id]
	return ok
}

// connStatus is a tuple of connection name and a count of the number of open
// connections.
type connStatus struct {
	name  string
	count int
}

// status returns the current status of the pool.
func (p *h2ConnPool) status() []connStatus {
	p.m.RLock()
	defer p.m.RUnlock()

	var status []connStatus
	for id, conns := range p.conns {
		status = append(status, connStatus{name: id, count: len(conns)})
	}

	return status
}
