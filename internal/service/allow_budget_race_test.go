//go:build race

package service

// Separate budgets account for additional race-instrumentation allocations.
const allowAllocationBudget = 70
