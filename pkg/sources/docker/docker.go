package docker

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	gzip "github.com/klauspost/pgzip"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_DOCKER

type Source struct {
	name        string
	sourceId    sources.SourceID
	jobId       sources.JobID
	verify      bool
	concurrency int
	conn        sourcespb.Docker
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time.
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

// Init initializes the source.
func (s *Source) Init(_ context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.concurrency = concurrency

	// Reset metrics for this source at initialization time.
	dockerImagesScanned.WithLabelValues(s.name).Set(0)
	dockerLayersScanned.WithLabelValues(s.name).Set(0)

	if err := anypb.UnmarshalTo(connection, &s.conn, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}

	return nil
}

type imageInfo struct {
	image v1.Image
	base  string
	tag   string
}

type layerInfo struct {
	digest v1.Hash
	base   string
	tag    string
}

// Chunks emits data over a channel that is decoded and scanned for secrets.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	ctx = context.WithValues(ctx, "source_type", s.Type(), "source_name", s.name)

	workers := new(errgroup.Group)
	workers.SetLimit(s.concurrency)

	for _, image := range s.conn.GetImages() {
		if common.IsDone(ctx) {
			return nil
		}

		imgInfo, err := s.processImage(ctx, image)
		if err != nil {
			ctx.Logger().Error(err, "error processing image", "image", image)
			return nil
		}

		ctx = context.WithValues(ctx, "image", imgInfo.base, "tag", imgInfo.tag)

		ctx.Logger().V(2).Info("scanning image config")

		if err := s.processConfig(ctx, imgInfo, chunksChan); err != nil {
			ctx.Logger().Error(err, "error processing image config")
			return nil
		}
		dockerImageConfigsScanned.WithLabelValues(s.name).Inc()

		ctx.Logger().V(2).Info("scanning image layers")

		layers, err := imgInfo.image.Layers()
		if err != nil {
			ctx.Logger().Error(err, "error getting image layers")
			return nil
		}

		for _, layer := range layers {
			workers.Go(func() error {
				if err := s.processLayer(ctx, layer, imgInfo, chunksChan); err != nil {
					ctx.Logger().Error(err, "error processing layer")
					return nil
				}
				dockerLayersScanned.WithLabelValues(s.name).Inc()

				return nil
			})
		}

		if err := workers.Wait(); err != nil {
			ctx.Logger().Error(err, "error processing layers")
			return nil
		}

		dockerImagesScanned.WithLabelValues(s.name).Inc()
	}

	return nil
}

// processImage processes an individual image and prepares it for further processing.
func (s *Source) processImage(ctx context.Context, image string) (imageInfo, error) {
	var (
		imgInfo   imageInfo
		hasDigest bool
		imageName name.Reference
	)

	remoteOpts, err := s.remoteOpts()
	if err != nil {
		return imgInfo, err
	}

	const filePrefix = "file://"
	if strings.HasPrefix(image, filePrefix) {
		image = strings.TrimPrefix(image, filePrefix)
		imgInfo.base = image
		imgInfo.image, err = tarball.ImageFromPath(image, nil)
		if err != nil {
			return imgInfo, err
		}
	} else {
		imgInfo.base, imgInfo.tag, hasDigest = baseAndTagFromImage(image)

		if hasDigest {
			imageName, err = name.NewDigest(image)
		} else {
			imageName, err = name.NewTag(image)
		}
		if err != nil {
			return imgInfo, err
		}

		imgInfo.image, err = remote.Image(imageName, remoteOpts...)
		if err != nil {
			return imgInfo, err
		}
	}

	ctx.Logger().WithValues("image", imgInfo.base, "tag", imgInfo.tag).V(2).Info("scanning image")

	return imgInfo, nil
}

// processConfig processes the image configuration metadata.
// The easiest way to view this metadata is by using "crane config [image]" https://github.com/google/go-containerregistry/tree/main/cmd/crane
func (s *Source) processConfig(ctx context.Context, imgInfo imageInfo, chunksChan chan *sources.Chunk) error {
	imgConfig, err := imgInfo.image.RawConfigFile()
	if err != nil {
		ctx.Logger().Error(err, "error getting image config")
		return err
	}

	// Make up an identifier for this entry that is moderately sensible. There is
	// no file name to use here, so the path tries to be a little descriptive.
	entryPath := "image-metadata:config"

	chunk := &sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Docker{
				Docker: &source_metadatapb.Docker{
					File:  entryPath,
					Image: imgInfo.base,
					Tag:   imgInfo.tag,
				},
			},
		},
		Verify: s.verify,
		Data:   imgConfig,
	}

	return common.CancellableWrite(ctx, chunksChan, chunk)
}

// processLayer processes an individual layer of an image.
func (s *Source) processLayer(ctx context.Context, layer v1.Layer, imgInfo imageInfo, chunksChan chan *sources.Chunk) error {
	layerInfo := layerInfo{
		base: imgInfo.base,
		tag:  imgInfo.tag,
	}

	var err error
	layerInfo.digest, err = layer.Digest()
	if err != nil {
		return err
	}

	ctx.Logger().WithValues("layer", layerInfo.digest.String()).V(2).Info("scanning layer")

	rc, err := layer.Compressed()
	if err != nil {
		return err
	}
	defer rc.Close()

	const (
		defaultBlockSize = 1 << 24 // 16MB
		defaultBlocks    = 8
	)

	gzipReader, err := gzip.NewReaderN(rc, defaultBlockSize, defaultBlocks)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		info := chunkProcessingInfo{size: header.Size, name: header.Name, reader: tarReader, layer: layerInfo}
		if err := s.processChunk(ctx, info, chunksChan); err != nil {
			return err
		}
	}

	return nil
}

type chunkProcessingInfo struct {
	size   int64
	name   string
	reader io.Reader
	layer  layerInfo
}

// processChunk processes an individual chunk of a layer.
func (s *Source) processChunk(ctx context.Context, info chunkProcessingInfo, chunksChan chan *sources.Chunk) error {
	const filesizeLimitBytes int64 = 50 * 1024 * 1024 // 50MB
	if info.size > filesizeLimitBytes {
		ctx.Logger().V(2).Info("skipping file: size exceeds max allowed", "file", info.name, "size", info.size, "limit", filesizeLimitBytes)
		return nil
	}

	chunkReader := sources.NewChunkReader()
	chunkResChan := chunkReader(ctx, info.reader)

	for data := range chunkResChan {
		if err := data.Error(); err != nil {
			ctx.Logger().Error(err, "error reading chunk.")
			continue
		}

		chunk := &sources.Chunk{
			SourceType: s.Type(),
			SourceName: s.name,
			SourceID:   s.SourceID(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Docker{
					Docker: &source_metadatapb.Docker{
						File:  "/" + info.name,
						Image: info.layer.base,
						Tag:   info.layer.tag,
						Layer: info.layer.digest.String(),
					},
				},
			},
			Verify: s.verify,
		}
		chunk.Data = data.Bytes()

		if err := common.CancellableWrite(ctx, chunksChan, chunk); err != nil {
			return err
		}
	}

	return nil
}

func (s *Source) remoteOpts() ([]remote.Option, error) {
	defaultTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          s.concurrency * 4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   s.concurrency * 2,
	}

	var opts []remote.Option
	opts = append(opts, remote.WithTransport(defaultTransport))

	switch s.conn.GetCredential().(type) {
	case *sourcespb.Docker_Unauthenticated:
		return nil, nil
	case *sourcespb.Docker_BasicAuth:
		opts = append(opts, remote.WithAuth(&authn.Basic{
			Username: s.conn.GetBasicAuth().GetUsername(),
			Password: s.conn.GetBasicAuth().GetPassword(),
		}))
	case *sourcespb.Docker_BearerToken:
		opts = append(opts, remote.WithAuth(&authn.Bearer{
			Token: s.conn.GetBearerToken(),
		}))
	case *sourcespb.Docker_DockerKeychain:
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	default:
		return nil, fmt.Errorf("unknown credential type: %T", s.conn.Credential)
	}

	return opts, nil
}

func baseAndTagFromImage(image string) (base, tag string, hasDigest bool) {
	if base, tag, hasDigest = extractDigest(image); hasDigest {
		return base, tag, true
	}

	base, tag = extractTagOrUseDefault(image)
	return base, tag, false
}

// extractDigest tries to split the image string on the digest delimiter.
// If successful, it means the image has a digest.
func extractDigest(image string) (base, tag string, hasDigest bool) {
	const digestDelim = "@"

	if parts := strings.SplitN(image, digestDelim, 2); len(parts) > 1 {
		return parts[0], parts[1], true
	}
	return "", "", false
}

// extractTagOrUseDefault extracts the tag from the image string.
// If no tag is found, it defaults to "latest".
func extractTagOrUseDefault(image string) (base, tag string) {
	const (
		tagDelim     = ":"
		regRepoDelim = "/"
	)

	parts := strings.Split(image, tagDelim)

	// Check if the last part is not a hostname with a port (for weak validation)
	if len(parts) > 1 && !strings.Contains(parts[len(parts)-1], regRepoDelim) {
		return strings.Join(parts[:len(parts)-1], tagDelim), parts[len(parts)-1]
	}
	return image, "latest"
}
