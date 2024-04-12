package main

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/paulbellamy/ratecounter"
	"golang.org/x/sync/semaphore"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

var (
	// CLI flags and commands
	app = kingpin.New("Snifftest", "Test secret detectors against data sets.")

	showDetectorsCmd = app.Command("show-detectors", "Shows the available detectors.")

	scanCmd           = app.Command("scan", "Scans data.")
	scanCmdDetector   = scanCmd.Flag("detector", "Detector to scan with. 'all', or a specific name.").Default("all").String()
	scanCmdExclude    = scanCmd.Flag("exclude", "Detector(s) to exclude").Strings()
	scanCmdRepo       = scanCmd.Flag("repo", "URI to .git repo.").Required().String()
	scanThreshold     = scanCmd.Flag("fail-threshold", "Result threshold that causes failure for a single scanner.").Int()
	scanPrintRes      = scanCmd.Flag("print", "Print results.").Bool()
	scanPrintChunkRes = scanCmd.Flag("print-chunk", "Print chunks that have results.").Bool()
	scanVerify        = scanCmd.Flag("verify", "Verify found secrets.").Bool()
)

func main() {
	// setup logger
	logger, flush := log.New("trufflehog", log.WithConsoleSink(os.Stderr))
	// make it the default logger for contexts
	context.SetDefaultLogger(logger)
	defer func() { _ = flush() }()
	logFatal := func(err error, message string, keyAndVals ...any) {
		logger.Error(err, message, keyAndVals...)
		if err != nil {
			os.Exit(1)
			return
		}
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Hour*2)
	var cancelOnce sync.Once
	defer cancelOnce.Do(cancel)

	cmd := kingpin.MustParse(app.Parse(os.Args[1:]))

	switch cmd {
	case scanCmd.FullCommand():

		chunksChan := make(chan *sources.Chunk, 10000)

		var wgChunkers sync.WaitGroup

		sem := semaphore.NewWeighted(int64(runtime.NumCPU()))

		selectedScanners := map[string]detectors.Detector{}
		allScanners := getAllScanners()

		allDecoders := decoders.DefaultDecoders()

		input := strings.ToLower(*scanCmdDetector)
		if input == "all" {
			selectedScanners = allScanners
		} else {
			_, ok := allScanners[input]
			if !ok {
				logFatal(fmt.Errorf("invalid input"), "could not find scanner by that name")
			}
			selectedScanners[input] = allScanners[input]
		}
		if len(selectedScanners) == 0 {
			logFatal(fmt.Errorf("invalid input"), "no detectors selected")
		}

		for _, excluded := range *scanCmdExclude {
			delete(selectedScanners, excluded)
		}

		logger.Info("loaded secret detectors", "count", len(selectedScanners)+3)

		var wgScanners sync.WaitGroup

		var chunkCounter uint64
		go func() {
			counter := ratecounter.NewRateCounter(60 * time.Second)
			var prev uint64
			for {
				time.Sleep(60 * time.Second)
				counter.Incr(int64(chunkCounter - prev))
				prev = chunkCounter
				logger.Info("chunk scan rate per second", "rate", counter.Rate()/60)
			}
		}()

		resCounter := make(map[string]*uint64)
		failed := false

		for i := 0; i < runtime.NumCPU(); i++ {
			wgScanners.Add(1)

			go func() {
				defer wgScanners.Done()

				for chunk := range chunksChan {
					for name, scanner := range selectedScanners {
						for _, dec := range allDecoders {
							decoded := dec.FromChunk(&sources.Chunk{Data: chunk.Data})
							if decoded != nil {
								foundKeyword := false
								for _, kw := range scanner.Keywords() {
									if strings.Contains(strings.ToLower(string(decoded.Data)), strings.ToLower(kw)) {
										foundKeyword = true
									}
								}
								if !foundKeyword {
									continue
								}

								res, err := scanner.FromData(ctx, *scanVerify, decoded.Data)
								if err != nil {
									logFatal(err, "error scanning chunk")
								}
								if len(res) > 0 {
									if resCounter[name] == nil {
										zero := uint64(0)
										resCounter[name] = &zero
									}
									atomic.AddUint64(resCounter[name], uint64(len(res)))
									if *scanThreshold != 0 && int(*resCounter[name]) > *scanThreshold {
										logger.Error(
											fmt.Errorf("exceeded result threshold"), "snifftest failed",
											"scanner", name, "threshold", *scanThreshold,
										)
										failed = true
										os.Exit(1)
									}

									if *scanPrintRes {
										for _, r := range res {
											logger := logger.WithValues("secret", name, "meta", chunk.SourceMetadata, "result", string(r.Raw))
											if *scanPrintChunkRes {
												logger = logger.WithValues("chunk", string(decoded.Data))
											}
											logger.Info("result")
										}
									}
								}
							}
						}
					}

					atomic.AddUint64(&chunkCounter, uint64(1))
				}
			}()
		}

		for _, repo := range strings.Split(*scanCmdRepo, ",") {
			if err := sem.Acquire(ctx, 1); err != nil {
				logFatal(err, "timed out waiting for semaphore")
			}
			wgChunkers.Add(1)
			go func(r string) {
				defer sem.Release(1)
				defer wgChunkers.Done()
				logger.Info("cloning repo", "repo", r)
				path, repo, err := git.CloneRepoUsingUnauthenticated(ctx, r)
				if err != nil {
					logFatal(err, "error cloning repo", "repo", r)
				}

				logger.Info("cloned repo", "repo", r)

				cfg := &git.Config{
					SourceName:   "snifftest",
					JobID:        0,
					SourceID:     0,
					SourceType:   sourcespb.SourceType_SOURCE_TYPE_GIT,
					Verify:       false,
					SkipBinaries: true,
					SkipArchives: false,
					Concurrency:  runtime.NumCPU(),
					SourceMetadataFunc: func(repository, commit, commitSource, email, timestamp, file string, line int64) *source_metadatapb.MetaData {
						return &source_metadatapb.MetaData{
							Data: &source_metadatapb.MetaData_Git{
								Git: &source_metadatapb.Git{
									Repository:   repository,
									Commit:       commit,
									CommitSource: commitSource,
									Email:        email,
									Timestamp:    timestamp,
									File:         file,
								},
							},
						}
					},
				}
				s := git.NewGit(cfg)

				logger.Info("scanning repo", "repo", r)
				err = s.ScanRepo(ctx, repo, path, git.NewScanOptions(), sources.ChanReporter{Ch: chunksChan})
				if err != nil {
					logFatal(err, "error scanning repo")
				}
				logger.Info("scanned repo", "repo", r)
				defer os.RemoveAll(path)
			}(repo)
		}

		go func() {
			wgChunkers.Wait()
			close(chunksChan)
		}()

		wgScanners.Wait()

		logger.Info("completed snifftest", "chunks", chunkCounter)
		for scanner, resultsCount := range resCounter {
			logger.Info(scanner, "results", *resultsCount)
		}

		if failed {
			os.Exit(1)
		}
	case showDetectorsCmd.FullCommand():
		for s := range getAllScanners() {
			fmt.Println(s)
		}
	}
}

func getAllScanners() map[string]detectors.Detector {
	allScanners := map[string]detectors.Detector{}
	for _, s := range defaults.DefaultDetectors() {
		secretType := reflect.Indirect(reflect.ValueOf(s)).Type().PkgPath()
		path := strings.Split(secretType, "/")[len(strings.Split(secretType, "/"))-1]
		allScanners[path] = s
	}
	return allScanners
}
