package bcrypt

import (
	"fmt"
	"testing"
)

const benchMaxCost = 15

func BenchmarkHasher_Hash(b *testing.B) {
	for cost := MinCost; cost <= benchMaxCost; cost++ {
		hasher := New(cost)

		b.Run(fmt.Sprint("cost", cost), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := hasher.Hash("verysecurepassword")
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
