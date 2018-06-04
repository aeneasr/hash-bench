// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"github.com/pborman/uuid"
	"log"
	"time"
	"math/rand"
	"sync/atomic"
	"fmt"
	"sync"
)

// bcryptCmd represents the bcrypt command
var bcryptCmd = &cobra.Command{
	Use: "bcrypt",
	Run: func(cmd *cobra.Command, args []string) {
		wf, _ := cmd.Flags().GetInt("workfactor")
		p, _ := cmd.Flags().GetInt("parallel")
		num, _ := cmd.Flags().GetInt("passwords")
		runFor, _ := cmd.Flags().GetDuration("time")

		var lock sync.Mutex
		passwords := make([][]byte, num)
		hashes := make([][]byte, num)

		fmt.Println("Generating passwords and password hashes.")
		for k := range passwords {
			passwords[k] = []byte(uuid.New())
		}

		var valid, invalid, generated uint64
		compareEvents := make(chan []int, 100)
		generateEvents := make(chan int, 100)

		var avgGenerated float64

		var wg sync.WaitGroup
		wg.Add(p)

		var generate = func() {
			defer wg.Done()
			for e := range generateEvents {
				h, err := bcrypt.GenerateFromPassword(passwords[e], wf)
				if err != nil {
					log.Fatalf("%+v", err)
				}

				atomic.AddUint64(&generated, 1)
				lock.Lock()
				hashes[e] = h
				lock.Unlock()
			}
		}

		var compare = func() {
			defer wg.Done()
			for e := range compareEvents {
				p := passwords[e[0]]
				h := hashes[e[1]]

				if err := bcrypt.CompareHashAndPassword(h, p); err != nil {
					atomic.AddUint64(&invalid, 1)
				} else {
					atomic.AddUint64(&valid, 1)
				}
			}
		}

		seed := rand.New(rand.NewSource(time.Now().Unix()))

		for i := 0; i < p; i++ {
			go compare()
		}

		for i := 0; i < p; i++ {
			go generate()
		}

		start := time.Now()
		var printStats = func() {
			totalEnd := time.Now()
			elapsed := totalEnd.Sub(start).Seconds()
			avgg := float64(generated)/elapsed
			if avgGenerated > 0 {
				avgg = avgGenerated
			}

			fmt.Printf(
				"Took %.2f seconds to generate %d and compare %d passwords (%d valid, %d invalid) (on average %.4f generated and %.4f validated per second)\n",
				elapsed,
				generated,
				valid+invalid,
				valid,
				invalid,
				avgg,float64(valid+invalid)/elapsed,
			)
		}

		go func() {
			for {
				time.Sleep(time.Second)
				printStats()
			}
		}()

		for k := range hashes {
			generateEvents <- k
		}
		close(generateEvents)

		wg.Wait()

		elapsed := time.Now().Sub(start).Seconds()
		avgGenerated = float64(generated)/elapsed
		printStats()

		wg.Add(p)

		start = time.Now()
		until := time.Now().Add(runFor)
		for time.Now().Before(until) {
			// 5% failed logins
			if seed.Intn(20) == 0 {
				compareEvents <- []int{seed.Intn(num), seed.Intn(num)}
			} else {
				n := seed.Intn(num)
				compareEvents <- []int{n, n}
			}
		}
		close(compareEvents)

		wg.Wait()

		printStats()
	},
}

func init() {
	RootCmd.AddCommand(bcryptCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// bcryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// bcryptCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	bcryptCmd.Flags().IntP("parallel", "p", 1, "")
	bcryptCmd.Flags().IntP("workfactor", "w", 10, "")
	bcryptCmd.Flags().IntP("passwords", "n", 100, "")
	bcryptCmd.Flags().DurationP("time", "t", time.Minute, "")
}
