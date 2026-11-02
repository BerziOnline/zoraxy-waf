//go:build race

package service

// Under -race, sync.Pool drops a random share of returned objects, so the
// average count moves by about one allocation between runs (measured 70-71).
// The strict budget is the one without race instrumentation.
const allowAllocationBudget = 73
