package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

const Samples = 10

func Benchmark(cost int, samples int, algorithm func(int) int) int {
	total_time := 0
	for i := 0; i < Samples; i++ {
		total_time += algorithm(cost)
	}
	return total_time / Samples
}

func benchmark_bcrypt(cost int) int {
	plaintext := make([]byte, 64)
	rand.Read(plaintext)
	start := time.Now()
	bcrypt.GenerateFromPassword(plaintext, cost)
	elapsed := time.Since(start)
	return int(elapsed / time.Millisecond)
}

func benchmark_pbkdf2_sha256(iterations int) int {
	plaintext := make([]byte, 64)
	salt := make([]byte, 16)
	rand.Read(plaintext)
	rand.Read(salt)
	start := time.Now()
	pbkdf2.Key(plaintext, salt, iterations, 64, sha256.New)
	elapsed := time.Since(start)
	return int(elapsed / time.Millisecond)
}

func benchmark_pbkdf2_sha512(iterations int) int {
	plaintext := make([]byte, 64)
	salt := make([]byte, 16)
	rand.Read(plaintext)
	rand.Read(salt)
	start := time.Now()
	pbkdf2.Key(plaintext, salt, iterations, 64, sha512.New)
	elapsed := time.Since(start)
	return int(elapsed / time.Millisecond)
}

func GetAlgorithm(algorithm string) func(int) int {
	switch algorithm {
	case "bcrypt":
		return benchmark_bcrypt
	case "pbkdf2-256":
		return benchmark_pbkdf2_sha256
	case "pbkdf2-512":
		return benchmark_pbkdf2_sha512
	default:
		panic("Unknown algorithm")
	}
}

func main() {
	algorithm := os.Args[1]
	costs := os.Args[2:]
	algo := GetAlgorithm(algorithm)
	for _, cost := range costs {
		cost_int, err := strconv.Atoi(cost)
		if err != nil {
			panic(err)
		}
		elapsed := Benchmark(cost_int, Samples, algo)
		fmt.Printf("%d, %d ms\n", cost_int, elapsed)
	}
}
