// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package graph

import (
	"sync"
)

// kvgraph implements Graph interface.
type kvgraph struct {
	rwLock sync.RWMutex
	graph  *graphR

	recordOldRevs  bool
	recordAgeLimit uint32
}

// NewGraph creates and new instance of key-value graph.
// <recordOldRevs> if enabled, will cause the graph to record the previous
// revisions of every node that have ever existed. <recordAgeLimit> is in minutes
// and allows to limit the maximum age of a record to keep, avoiding infinite
// memory usage growth.
func NewGraph(recordOldRevs bool, recordAgeLimit uint32) Graph {
	kvgraph := &kvgraph{
		recordOldRevs:  recordOldRevs,
		recordAgeLimit: recordAgeLimit,
	}
	kvgraph.graph = newGraphR()
	kvgraph.graph.parent = kvgraph
	return kvgraph
}

// Read returns a graph handle for read-only access.
// The graph supports multiple concurrent readers.
// Release eventually using Release() method.
func (kvgraph *kvgraph) Read() ReadAccess {
	kvgraph.rwLock.RLock()
	return kvgraph.graph
}

// Write returns a graph handle for read-write access.
// The graph supports at most one writer at a time - i.e. it is assumed
// there is no write-concurrency.
// The changes are propagated to the graph using Save().
// Release eventually using Release() method.
func (kvgraph *kvgraph) Write(record bool) RWAccess {
	return newGraphRW(kvgraph.graph, record)
}
