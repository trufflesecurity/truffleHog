package docker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Source struct {
	name     string
	sourceId int64
	jobId    int64
	verify   bool
	conn     sourcespb.Docker
	sources.Progress
}

var FilesizeLimitBytes int64 = 10 * 1024 * 1024 // 10MB

// Ensure the Source satisfies the interface at compile time.
var _ sources.Source = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_DOCKER
}

func (s *Source) SourceID() int64 {
	return s.sourceId
}

func (s *Source) JobID() int64 {
	return s.jobId
}

// Init initializes the source.
func (s *Source) Init(_ context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	if err := anypb.UnmarshalTo(connection, &s.conn, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}

	return nil
}

// Chunks emits data over a channel that is decoded and scanned for secrets.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	remoteOpts, err := s.remoteOpts()
	if err != nil {
		return err
	}

	for _, image := range s.conn.GetImages() {
		var img v1.Image
		var err error
		var base, tag string

		if strings.HasPrefix(image, "file://") {
			image = strings.TrimPrefix(image, "file://")
			base = image
			img, err = tarball.ImageFromPath(image, nil)
			if err != nil {
				return err
			}
		} else {
			base, tag = baseAndTagFromImage(image)
			imageName, err := name.NewTag(image)
			if err != nil {
				return err
			}

			img, err = remote.Image(imageName, remoteOpts...)
			if err != nil {
				return err
			}
		}

		layers, err := img.Layers()
		if err != nil {
			return err
		}

		for _, layer := range layers {
			digest, err := layer.Digest()
			if err != nil {
				return err
			}

			rc, err := layer.Compressed()
			if err != nil {
				return err
			}

			defer rc.Close()

			gzipReader, err := gzip.NewReader(rc)
			if err != nil {
				return err
			}

			defer gzipReader.Close()

			tarReader := tar.NewReader(gzipReader)

			for {
				header, err := tarReader.Next()
				if err == io.EOF {
					break // End of archive
				}
				if err != nil {
					return err
				}

				// Skip files larger than FilesizeLimitBytes
				if header.Size > FilesizeLimitBytes {
					continue
				}

				file := bytes.NewBuffer(nil)

				_, err = io.Copy(file, tarReader)
				if err != nil {
					return err
				}

				chunk := &sources.Chunk{
					SourceType: s.Type(),
					SourceName: s.name,
					SourceID:   s.SourceID(),
					Data:       file.Bytes(),
					SourceMetadata: &source_metadatapb.MetaData{
						Data: &source_metadatapb.MetaData_Docker{
							Docker: &source_metadatapb.Docker{
								File:  header.Name,
								Image: base,
								Tag:   tag,
								Layer: digest.String(),
							},
						},
					},
					Verify: s.verify,
				}

				chunksChan <- chunk
			}
		}
	}

	return nil
}

func baseAndTagFromImage(image string) (base, tag string) {
	regRepoDelimiter := "/"
	tagDelim := ":"
	parts := strings.Split(image, tagDelim)
	// Verify that we aren't confusing a tag for a hostname w/ port for the purposes of weak validation.
	if len(parts) > 1 && !strings.Contains(parts[len(parts)-1], regRepoDelimiter) {
		base = strings.Join(parts[:len(parts)-1], tagDelim)
		tag = parts[len(parts)-1]
	} else {
		base = image
		tag = "latest"
	}

	return
}

func (s *Source) remoteOpts() ([]remote.Option, error) {
	switch s.conn.GetCredential().(type) {
	case *sourcespb.Docker_Unauthenticated:
		return nil, nil
	case *sourcespb.Docker_BasicAuth:
		return []remote.Option{
			remote.WithAuth(&authn.Basic{
				Username: s.conn.GetBasicAuth().GetUsername(),
				Password: s.conn.GetBasicAuth().GetPassword(),
			}),
		}, nil
	case *sourcespb.Docker_BearerToken:
		return []remote.Option{
			remote.WithAuth(&authn.Bearer{
				Token: s.conn.GetBearerToken(),
			}),
		}, nil
	case *sourcespb.Docker_DockerKeychain:
		return []remote.Option{
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
		}, nil
	default:
		return nil, fmt.Errorf("unknown credential type: %T", s.conn.Credential)
	}
}
