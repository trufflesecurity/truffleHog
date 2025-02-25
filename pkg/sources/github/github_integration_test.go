//go:build integration
// +build integration

package github

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestSource_Token(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	githubPrivateKeyB64New := secret.MustGetField("GITHUB_PRIVATE_KEY_NEW")
	githubPrivateKeyBytesNew, err := base64.StdEncoding.DecodeString(githubPrivateKeyB64New)
	if err != nil {
		t.Fatal(err)
	}
	githubPrivateKeyNew := string(githubPrivateKeyBytesNew)
	githubInstallationIDNew := secret.MustGetField("GITHUB_INSTALLATION_ID_NEW")
	githubAppIDNew := secret.MustGetField("GITHUB_APP_ID_NEW")

	src := &sourcespb.GitHub{
		Endpoint: "https://api.github.com",
		Credential: &sourcespb.GitHub_GithubApp{
			GithubApp: &credentialspb.GitHubApp{
				PrivateKey:     githubPrivateKeyNew,
				InstallationId: githubInstallationIDNew,
				AppId:          githubAppIDNew,
			},
		},
	}
	conn, err := anypb.New(src)
	if err != nil {
		panic(err)
	}

	s := Source{
		conn:          src,
		memberCache:   map[string]struct{}{},
		repoInfoCache: newRepoInfoCache(),
	}
	s.Init(ctx, "github integration test source", 0, 0, false, conn, 1)
	s.filteredRepoCache = s.newFilteredRepoCache(ctx, simple.NewCache[string](), nil, nil)

	err = s.enumerateWithApp(ctx, s.connector.(*appConnector).InstallationClient(), noopReporter())
	assert.NoError(t, err)

	_, _, err = s.cloneRepo(ctx, "https://github.com/truffle-test-integration-org/another-test-repo.git")
	assert.NoError(t, err)
}

func TestSource_ScanComments(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	// For the personal access token test
	githubToken := secret.MustGetField("GITHUB_TOKEN")

	const totalPRChunks = 3
	const totalIssueChunks = 2

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.GitHub
	}
	tests := []struct {
		name              string
		init              init
		wantChunk         *sources.Chunk
		wantErr           bool
		minRepo           int
		minOrg            int
		numExpectedChunks int
	}{
		{
			name: "token authenticated, single repo, single issue comment",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories:               []string{"https://github.com/truffle-test-integration-org/another-test-repo.git"},
					IncludeIssueComments:       true,
					IncludePullRequestComments: false,
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			numExpectedChunks: totalIssueChunks,
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Link:      "https://github.com/truffle-test-integration-org/another-test-repo/issues/1",
							Username:  "truffle-sandbox",
							Timestamp: "2023-06-22 23:33:46 +0000 UTC",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		{
			name: "token authenticated, single repo, pull request comment",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories:               []string{"https://github.com/truffle-test-integration-org/another-test-repo.git"},
					IncludePullRequestComments: true,
					IncludeIssueComments:       false,
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			numExpectedChunks: totalPRChunks,
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Link:      "https://github.com/truffle-test-integration-org/another-test-repo/pull/2#discussion_r1242763304",
							Username:  "truffle-sandbox",
							Timestamp: "2023-06-26 21:00:11 +0000 UTC",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 4)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				// Close the channel
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					if ctx.Err() != nil {
						return
					}
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}()

			i := 0
			for gotChunk := range chunksCh {
				// Skip chunks that are not comments.
				if gotChunk.SourceMetadata.GetGithub().GetCommit() != "" {
					continue
				}
				i++
				githubCommentCheckFunc(gotChunk, tt.wantChunk, i, t, tt.name)
			}

			// Confirm all comments were processed.
			if i != tt.numExpectedChunks {
				t.Errorf("did not complete all chunks, got %d, want %d", i, tt.numExpectedChunks)
			}

		})
	}
}

func TestSource_ScanChunks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	// For the personal access token test.
	githubToken := secret.MustGetField("GITHUB_TOKEN")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.GitHub
	}
	tests := []struct {
		name       string
		init       init
		wantChunks int
	}{
		{
			name: "token authenticated, 4 repos",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{
						"https://github.com/truffle-test-integration-org/another-test-repo.git",
						"https://github.com/trufflesecurity/trufflehog.git",
						"https://github.com/Akash-goyal-github/Inventory-Management-System.git",
						"https://github.com/R1ck404/Crypto-Exchange-Example.git",
						"https://github.com/Stability-AI/generative-models.git",
						"https://github.com/bloomberg/blazingmq.git",
						"https://github.com/Kong/kong.git",
					},
					Credential: &sourcespb.GitHub_Token{Token: githubToken},
				},
			},
			wantChunks: 20000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 8)
			assert.Nil(t, err)

			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				assert.Nil(t, err)
			}()

			i := 0
			for range chunksCh {
				i++
			}
			assert.GreaterOrEqual(t, i, tt.wantChunks)
		})
	}
}

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	// For the personal access token test
	githubToken := secret.MustGetField("GITHUB_TOKEN")

	// For the  NEW github app test (+Member enum)
	githubPrivateKeyB64New := secret.MustGetField("GITHUB_PRIVATE_KEY_NEW")
	githubPrivateKeyBytesNew, err := base64.StdEncoding.DecodeString(githubPrivateKeyB64New)
	if err != nil {
		t.Fatal(err)
	}
	githubPrivateKeyNew := string(githubPrivateKeyBytesNew)
	githubInstallationIDNew := secret.MustGetField("GITHUB_INSTALLATION_ID_NEW")
	githubAppIDNew := secret.MustGetField("GITHUB_APP_ID_NEW")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.GitHub
	}
	tests := []struct {
		name      string
		init      init
		wantChunk *sources.Chunk
		wantErr   bool
		minRepo   int
		minOrg    int
	}{
		{
			name: "token authenticated, single repo",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{"https://github.com/truffle-test-integration-org/another-test-repo.git"},
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://github.com/truffle-test-integration-org/another-test-repo.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		{
			name: "token authenticated, single repo, no .git",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{"https://github.com/truffle-test-integration-org/another-test-repo"},
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://github.com/truffle-test-integration-org/another-test-repo.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		{
			name: "token authenticated, single org",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Organizations: []string{"truffle-test-integration-org"},
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   1,
			minOrg:    1,
		},
		{
			name: "token authenticated, username in org",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Organizations: []string{"truffle-sandbox"},
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   2,
			minOrg:    1,
		},
		{
			name: "token authenticated, no org or user (enum)",
			// This configuration currently will only find gists from the user. No repos or orgs will be scanned.
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   2,
			minOrg:    0,
		},
		{
			name: "unauthenticated, single org",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Organizations: []string{"trufflesecurity"},
					Credential:    &sourcespb.GitHub_Unauthenticated{},
					IncludeForks:  true,
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   40,
			minOrg:    1,
		},
		{
			name: "unauthenticated, single repo",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{"https://github.com/trufflesecurity/driftwood.git"},
					Credential:   &sourcespb.GitHub_Unauthenticated{},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://github.com/trufflesecurity/driftwood.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		{
			name: "app authenticated, no repo or org",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					ScanUsers: true,
					Credential: &sourcespb.GitHub_GithubApp{
						GithubApp: &credentialspb.GitHubApp{
							PrivateKey:     githubPrivateKeyNew,
							InstallationId: githubInstallationIDNew,
							AppId:          githubAppIDNew,
						},
					},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   32,
			minOrg:    0,
		},
		{
			name: "app authenticated, single repo",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{"https://github.com/truffle-test-integration-org/another-test-repo.git"},
					Credential: &sourcespb.GitHub_GithubApp{
						GithubApp: &credentialspb.GitHubApp{
							PrivateKey:     githubPrivateKeyNew,
							InstallationId: githubInstallationIDNew,
							AppId:          githubAppIDNew,
						},
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://github.com/truffle-test-integration-org/another-test-repo.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
			minRepo: 1,
			minOrg:  0,
		},
		{
			name: "app authenticated, single org",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Organizations: []string{"truffle-test-integration-org"},
					Credential: &sourcespb.GitHub_GithubApp{
						GithubApp: &credentialspb.GitHubApp{
							PrivateKey:     githubPrivateKeyNew,
							InstallationId: githubInstallationIDNew,
							AppId:          githubAppIDNew,
						},
					},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   1,
			minOrg:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 4)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 5)
			go func() {
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					if ctx.Err() != nil {
						return
					}
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}()
			if err = sources.HandleTestChannel(chunksCh, basicCheckFunc(tt.minOrg, tt.minRepo, tt.wantChunk, &s)); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestSource_paginateGists(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.GitHub
	}
	tests := []struct {
		name      string
		init      init
		wantChunk *sources.Chunk
		wantErr   bool
		user      string
		minRepos  int
	}{
		{
			name: "get gist",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Credential: &sourcespb.GitHub_Unauthenticated{},
				},
			},
			wantChunk: &sources.Chunk{
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://gist.github.com/fecf272c606ddbc5f8486f9c44821312.git",
						},
					},
				},
				Verify: false,
			},
			wantErr:  false,
			user:     "truffle-sandbox",
			minRepos: 1,
		},
		{
			name: "get multiple pages of gists",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Credential: &sourcespb.GitHub_Unauthenticated{},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			user:      "andrew",
			minRepos:  101,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 4)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 5)
			go func() {
				assert.NoError(t, s.addUserGistsToCache(ctx, tt.user, noopReporter()))
				chunksCh <- &sources.Chunk{}
			}()
			var wantedRepo string
			if tt.wantChunk != nil {
				wantedRepo = tt.wantChunk.SourceMetadata.GetGithub().Repository
			}
			if err = sources.HandleTestChannel(chunksCh, gistsCheckFunc(wantedRepo, tt.minRepos, &s)); err != nil {
				t.Error(err)
			}
		})
	}
}

func gistsCheckFunc(expected string, minRepos int, s *Source) sources.ChunkFunc {
	return func(chunk *sources.Chunk) error {
		if minRepos != 0 && minRepos > s.filteredRepoCache.Count() {
			return fmt.Errorf("didn't find enough repos. expected: %d, got :%d", minRepos, len(s.repos))
		}
		if expected != "" {
			for _, repo := range s.filteredRepoCache.Values() {
				if repo == expected {
					return nil
				}
			}
			return fmt.Errorf("expected repo not included: %s", expected)
		}
		return nil
	}
}

func basicCheckFunc(minOrg, minRepo int, wantChunk *sources.Chunk, s *Source) sources.ChunkFunc {
	return func(chunk *sources.Chunk) error {
		if minOrg != 0 && minOrg > s.orgsCache.Count() {
			return fmt.Errorf("incorrect number of orgs. expected at least: %d, got %d", minOrg, s.orgsCache.Count())
		}
		if minRepo != 0 && minRepo > len(s.repos) {
			return fmt.Errorf("incorrect number of repos. expected at least: %d, got %d", minRepo, len(s.repos))
		}
		if wantChunk != nil {
			if diff := pretty.Compare(chunk.SourceMetadata.GetGithub().Repository, wantChunk.SourceMetadata.GetGithub().Repository); diff == "" {
				return nil
			}
			return sources.MatchError
		}
		return nil
	}
}

func githubCommentCheckFunc(gotChunk, wantChunk *sources.Chunk, i int, t *testing.T, name string) {
	if gotChunk.SourceType != wantChunk.SourceType {
		t.Errorf("want SourceType %v, got %v", wantChunk.SourceType, gotChunk.SourceType)
	}

	assert.NotEmpty(t, gotChunk.SourceMetadata.Data, "SourceMetadata.Data should not be empty")

	// First Chunk should be a Issue Comment, Second Chunk should be a PR Comment.
	if i == 1 && name == "token authenticated, single repo, single issue comment" &&
		wantChunk.SourceMetadata.GetGithub().GetLink() != gotChunk.SourceMetadata.GetGithub().GetLink() {
		t.Errorf("want %+v \n got %+v \n", wantChunk.SourceMetadata.GetGithub().GetLink(), gotChunk.SourceMetadata.GetGithub().GetLink())
	} else if i == 2 && name == "token authenticated, single repo, single pr comment" &&
		wantChunk.SourceMetadata.GetGithub().GetLink() != gotChunk.SourceMetadata.GetGithub().GetLink() {
		t.Errorf("want %+v \n got %+v \n", wantChunk.SourceMetadata.GetGithub().GetLink(), gotChunk.SourceMetadata.GetGithub().GetLink())
	}
}

func TestSource_Chunks_TargetedScan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3000)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	githubToken := secret.MustGetField("GITHUB_TOKEN")

	type init struct {
		name          string
		verify        bool
		connection    *sourcespb.GitHub
		queryCriteria *source_metadatapb.MetaData
	}
	tests := []struct {
		name       string
		init       init
		wantChunks int
		wantErr    bool
	}{
		{
			name: "targeted scan, one file in small commit",
			init: init{
				name:       "test source",
				connection: &sourcespb.GitHub{Credential: &sourcespb.GitHub_Token{Token: githubToken}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "test-secrets",
							Link:       "https://github.com/truffle-sandbox/test-secrets/blob/0416560b1330d8ac42045813251d85c688717eaf/new_key#L2",
							Commit:     "0416560b1330d8ac42045813251d85c688717eaf",
							File:       "new_key",
						},
					},
				},
			},
			wantChunks: 1,
		},
		{
			name: "targeted scan, one file in med commit",
			init: init{
				name:       "test source",
				connection: &sourcespb.GitHub{Credential: &sourcespb.GitHub_Unauthenticated{}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://github.com/trufflesecurity/trufflehog.git",
							Link:       "https://github.com/trufflesecurity/trufflehog/blob/33eed42e17fda8b1a66feaeafcd57efccff26c11/pkg/sources/s3/s3_test.go#L78",
							Commit:     "33eed42e17fda8b1a66feaeafcd57efccff26c11",
							File:       "pkg/sources/s3/s3_test.go",
						},
					},
				},
			},
			wantChunks: 1,
		},
		{
			name: "targeted scan, binary file",
			init: init{
				name:       "test source",
				connection: &sourcespb.GitHub{Credential: &sourcespb.GitHub_Token{Token: githubToken}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://github.com/truffle-sandbox/test-secrets.git",
							Link:       "https://github.com/truffle-sandbox/test-secrets/blob/70bef8590f87257c0992eecc7db529827a12b801/null_text_w_ptp.ipynb",
							Commit:     "70bef8590f87257c0992eecc7db529827a12b801",
							File:       "null_text_w_ptp.ipynb",
						},
					},
				},
			},
			wantChunks: 607,
		},
		{
			name: "no file in commit",
			init: init{
				name:       "test source",
				connection: &sourcespb.GitHub{Credential: &sourcespb.GitHub_Unauthenticated{}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "test_keys",
							Link:       "https://github.com/trufflesecurity/test_keys/blob/fbc14303ffbf8fb1c2c1914e8dda7d0121633aca/keys#L4",
							Commit:     "fbc14303ffbf8fb1c2c1914e8dda7d0121633aca",
							File:       "not-the-file",
						},
					},
				},
			},
			wantChunks: 0,
			wantErr:    true,
		},
		{
			name: "invalid query criteria, malformed link",
			init: init{
				name:       "test source",
				connection: &sourcespb.GitHub{Credential: &sourcespb.GitHub_Unauthenticated{}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "test_keys",
							Link:       "malformed-link",
							Commit:     "fbc14303ffbf8fb1c2c1914e8dda7d0121633aca",
							File:       "not-the-file",
						},
					},
				},
			},
			wantChunks: 0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			assert.Nil(t, err)

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 8)
			assert.Nil(t, err)

			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh, sources.ChunkingTarget{QueryCriteria: tt.init.queryCriteria})
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			}()

			i := 0
			for range chunksCh {
				i++
			}
			assert.Equal(t, tt.wantChunks, i)
		})
	}
}

func TestChunkUnit(t *testing.T) {
	ctx := context.Background()
	conn, _ := anypb.New(&sourcespb.GitHub{
		Repositories: []string{"https://github.com/trufflesecurity/driftwood.git"},
		Credential:   &sourcespb.GitHub_Unauthenticated{},
	})
	s := Source{}
	if err := s.Init(ctx, "github integration test source", 0, 0, false, conn, 1); err != nil {
		t.Errorf("Init() failed: %v", err)
	}

	unit := RepoUnit{Name: "driftwood", URL: "https://github.com/trufflesecurity/driftwood.git"}
	reporter := &countChunkReporter{}
	if err := s.ChunkUnit(ctx, unit, reporter); err != nil {
		t.Errorf("ChunkUnit() failed: %v", err)
	}
	assert.GreaterOrEqual(t, reporter.chunkCount, 65)
	assert.Equal(t, 0, reporter.errCount)
}

type countChunkReporter struct {
	chunkCount int
	errCount   int
}

func (m *countChunkReporter) ChunkOk(ctx context.Context, chunk sources.Chunk) {
	m.chunkCount++
}

func (m *countChunkReporter) ChunkErr(ctx context.Context, err error) {
	m.errCount++
}
