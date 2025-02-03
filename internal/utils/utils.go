package utils

// GenerateSubsets generates all subsets of size n from the given nums slice.
func GenerateSubsets(nums []int, n int) [][]int {
	if n > len(nums) {
		panic("subset size cannot be greater than the number of elements in the set")
	}
	if n == 0 {
		return [][]int{{}}
	}
	if n == len(nums) {
		tmp := make([]int, n)
		copy(tmp, nums)
		return [][]int{tmp}
	}

	// Exclude the last element
	subsets := GenerateSubsets(nums[:len(nums)-1], n)

	// Include the last element in each subset of size (n-1)
	part2 := GenerateSubsets(nums[:len(nums)-1], n-1)
	for _, e := range part2 {
		subsets = append(subsets, append(e, nums[len(nums)-1]))
	}

	return subsets
}
