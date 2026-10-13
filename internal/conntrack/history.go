package conntrack

// connectionTable indexes by tuple and then by optional conntrack ID. A missing
// ID may match only an unambiguous tuple; two different known IDs never match.
type connectionTable[T any] struct {
	values map[connKey]map[uint32]T
	count  int
}

func newConnectionTable[T any]() *connectionTable[T] {
	return &connectionTable[T]{values: make(map[connKey]map[uint32]T)}
}

func tupleKey(key connKey) connKey { key.ID = 0; return key }

func (t *connectionTable[T]) set(key connKey, value T) {
	tuple := tupleKey(key)
	bucket := t.values[tuple]
	if bucket == nil {
		bucket = make(map[uint32]T)
		t.values[tuple] = bucket
	}
	if _, exists := bucket[key.ID]; !exists {
		t.count++
	}
	bucket[key.ID] = value
}

func (t *connectionTable[T]) exact(key connKey) (T, bool) {
	value, exists := t.values[tupleKey(key)][key.ID]
	return value, exists
}

func (t *connectionTable[T]) find(key connKey) (connKey, T, bool) {
	bucket := t.values[tupleKey(key)]
	if value, exists := bucket[key.ID]; exists {
		return key, value, true
	}
	if key.ID != 0 {
		if value, exists := bucket[0]; exists {
			return tupleKey(key), value, true
		}
	} else if len(bucket) == 1 {
		for id, value := range bucket {
			key.ID = id
			return key, value, true
		}
	}
	var zero T
	return connKey{}, zero, false
}

func (t *connectionTable[T]) remove(key connKey) {
	tuple := tupleKey(key)
	bucket := t.values[tuple]
	if _, exists := bucket[key.ID]; !exists {
		return
	}
	delete(bucket, key.ID)
	t.count--
	if len(bucket) == 0 {
		delete(t.values, tuple)
	}
}

func (t *connectionTable[T]) each(fn func(connKey, T)) {
	for tuple, bucket := range t.values {
		for id, value := range bucket {
			key := tuple
			key.ID = id
			fn(key, value)
		}
	}
}

// Bound unconfirmed disappeared connections even if the event socket silently
// loses events. On overflow the engine explicitly rebaselines rather than
// evicting a baseline and later counting its lifetime bytes a second time.
const maxRetiredBaselines = 65536
