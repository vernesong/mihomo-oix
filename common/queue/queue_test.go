package queue

import (
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestQueuePut tests the Put method of Queue
func TestQueuePut(t *testing.T) {
	// Initialize a new queue
	q := New[int](10)

	// Test putting a single item
	q.Put(1)
	assert.Equal(t, int64(1), q.Len(), "Queue length should be 1 after putting one item")

	// Test putting multiple items
	q.Put(2, 3, 4)
	assert.Equal(t, int64(4), q.Len(), "Queue length should be 4 after putting three more items")

	// Test putting zero items (should not change queue)
	q.Put()
	assert.Equal(t, int64(4), q.Len(), "Queue length should remain unchanged when putting zero items")
}

// TestQueuePop tests the Pop method of Queue
func TestQueuePop(t *testing.T) {
	// Initialize a new queue with items
	q := New[int](10)
	q.Put(1, 2, 3)

	// Test popping items in FIFO order
	item := q.Pop()
	assert.Equal(t, 1, item, "First item popped should be 1")
	assert.Equal(t, int64(2), q.Len(), "Queue length should be 2 after popping one item")

	item = q.Pop()
	assert.Equal(t, 2, item, "Second item popped should be 2")
	assert.Equal(t, int64(1), q.Len(), "Queue length should be 1 after popping two items")

	item = q.Pop()
	assert.Equal(t, 3, item, "Third item popped should be 3")
	assert.Equal(t, int64(0), q.Len(), "Queue length should be 0 after popping all items")
}

// TestQueuePopEmpty tests the Pop method on an empty queue
func TestQueuePopEmpty(t *testing.T) {
	// Initialize a new empty queue
	q := New[int](0)

	// Test popping from an empty queue
	item := q.Pop()
	assert.Equal(t, 0, item, "Popping from an empty queue should return the zero value")
	assert.Equal(t, int64(0), q.Len(), "Queue length should remain 0 after popping from an empty queue")
}

// TestQueueLast tests the Last method of Queue
func TestQueueLast(t *testing.T) {
	// Initialize a new queue with items
	q := New[int](10)
	q.Put(1, 2, 3)

	// Test getting the last item
	item := q.Last()
	assert.Equal(t, 3, item, "Last item should be 3")
	assert.Equal(t, int64(3), q.Len(), "Queue length should remain unchanged after calling Last")

	// Test Last on an empty queue
	emptyQ := New[int](0)
	emptyItem := emptyQ.Last()
	assert.Equal(t, 0, emptyItem, "Last on an empty queue should return the zero value")
}

// TestQueueCopy tests the Copy method of Queue
func TestQueueCopy(t *testing.T) {
	// Initialize a new queue with items
	q := New[int](10)
	q.Put(1, 2, 3)

	// Test copying the queue
	copy := q.Copy()
	assert.Equal(t, 3, len(copy), "Copy should have the same number of items as the original queue")
	assert.Equal(t, 1, copy[0], "First item in copy should be 1")
	assert.Equal(t, 2, copy[1], "Second item in copy should be 2")
	assert.Equal(t, 3, copy[2], "Third item in copy should be 3")

	// Verify that modifying the copy doesn't affect the original queue
	copy[0] = 99
	assert.Equal(t, 1, q.Pop(), "Original queue should not be affected by modifying the copy")
}

// TestQueueLen tests the Len method of Queue
func TestQueueLen(t *testing.T) {
	// Initialize a new empty queue
	q := New[int](10)
	assert.Equal(t, int64(0), q.Len(), "New queue should have length 0")

	// Add items and check length
	q.Put(1, 2)
	assert.Equal(t, int64(2), q.Len(), "Queue length should be 2 after putting two items")

	// Remove an item and check length
	q.Pop()
	assert.Equal(t, int64(1), q.Len(), "Queue length should be 1 after popping one item")
}

// TestQueueNew tests the New constructor
func TestQueueNew(t *testing.T) {
	// Test creating a new queue with different hints
	q1 := New[int](0)
	assert.NotNil(t, q1, "New queue should not be nil")
	assert.Equal(t, int64(0), q1.Len(), "New queue should have length 0")

	q2 := New[int](10)
	assert.NotNil(t, q2, "New queue should not be nil")
	assert.Equal(t, int64(0), q2.Len(), "New queue should have length 0")

	// Test with a different type
	q3 := New[string](5)
	assert.NotNil(t, q3, "New queue should not be nil")
	assert.Equal(t, int64(0), q3.Len(), "New queue should have length 0")
}

// Exercise the public methods while producers, consumers and readers overlap.
func TestQueueConcurrency(t *testing.T) {
	q := New[int](100)
	const workers, operations = 10, 100
	consumed := make(chan int, workers*operations)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Go(func() {
			for j := range operations {
				q.Put(i*operations + j + 1)
				_ = q.Last()
				_ = q.Copy()
				consumed <- q.Pop()
				runtime.Gosched()
			}
		})
	}
	wg.Wait()
	close(consumed)
	seen := make(map[int]bool)
	for item := range consumed {
		if item == 0 || seen[item] {
			t.Fatalf("lost or duplicated item: %d", item)
		}
		seen[item] = true
	}
	assert.Equal(t, workers*operations, len(seen))
	assert.Equal(t, int64(0), q.Len())
}

func TestQueuePopReleasesReferences(t *testing.T) {
	q := New[*int](2)
	first, second := new(int), new(int)
	q.Put(first, second)
	backing := q.items
	if q.Pop() != first || backing[0] != nil {
		t.Fatal("consumed slot retains its object")
	}
	if q.Pop() != second || backing[1] != nil {
		t.Fatal("last consumed slot retains its object")
	}
	if q.items != nil {
		t.Fatal("empty queue retains its backing array")
	}
}

// TestQueueWithDifferentTypes tests the Queue with different types
func TestQueueWithDifferentTypes(t *testing.T) {
	// Test with string type
	qString := New[string](5)
	qString.Put("hello", "world")
	assert.Equal(t, int64(2), qString.Len(), "Queue length should be 2")
	assert.Equal(t, "hello", qString.Pop(), "First item should be 'hello'")
	assert.Equal(t, "world", qString.Pop(), "Second item should be 'world'")

	// Test with struct type
	type Person struct {
		Name string
		Age  int
	}

	qStruct := New[Person](5)
	qStruct.Put(Person{Name: "Alice", Age: 30}, Person{Name: "Bob", Age: 25})
	assert.Equal(t, int64(2), qStruct.Len(), "Queue length should be 2")

	firstPerson := qStruct.Pop()
	assert.Equal(t, "Alice", firstPerson.Name, "First person's name should be 'Alice'")
	secondPerson := qStruct.Pop()
	assert.Equal(t, "Bob", secondPerson.Name, "Second person's name should be 'Bob'")
}
