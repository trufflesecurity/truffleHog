package token

import (
	"crypto/tls"
	"errors"
	"net/http"

	"golang.org/x/exp/maps"
	"golang.org/x/sync/singleflight"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/npm/registry"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type BaseScanner struct {
	client *http.Client
}

func (s BaseScanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NpmToken
}

func (s BaseScanner) Description() string {
	return "NPM tokens are used to authenticate with NPM registries."
}

type verifyResult struct {
	IsVerified bool
	ExtraData  map[string]string
	Error      error
}

var (
	noSuchHostCache   = simple.NewCache[struct{}]()
	verificationGroup singleflight.Group
)

func (s BaseScanner) VerifyToken(
	ctx context.Context,
	data string,
	token string,
) (bool, map[string]string, error) {
	logger := ctx.Logger().WithName("npm")
	if s.client == nil {
		s.client = detectors.DetectorHttpClientWithNoLocalAddresses
	}

	// Locate registry URL(s) in the data string.
	registries := make(map[string]*registry.Info)
	if r := registry.FindTokenURL(data, token); r != nil {
		// A high-confidence match was found.
		// e.g., |token|="s3cret" and |data| contains "//npm.company.com/:_authToken=s3cret".
		registries[r.Uri] = r
		logger.V(4).Info("Found high-confidence match for token", "token", token, "registry", r.Uri)
	} else {
		// A high confidence match was not found.
		// Attempt to verify the token against any registries we can find.
		for uri, info := range registry.FindAllURLs(ctx, data, true) {
			registries[uri] = info
		}
		logger.V(4).Info("Found low-confidence matches for token", "token", token, "registries", maps.Keys(registries))
	}

	// Iterate through registries
	errs := make([]error, 0, len(registries))
	for uri, info := range registries {
		// Use cached value where possible.
		if noSuchHostCache.Exists(uri) {
			logger.V(3).Info("Skipping invalid registry", "registry", uri)
			continue
		}

		r, _, _ := verificationGroup.Do(uri+token, func() (any, error) {
			logger.V(4).Info("Testing potential registry", "registry", uri, "token", token)
			verified, extraData, err := doVerification(ctx, s.client, info, token)
			if err != nil {
				// TODO: narrow this in scope? Known hosts like `github.com` should be exempt.
				if common.ErrIsNoSuchHost(err) {
					noSuchHostCache.Set(uri, struct{}{})
				}
			}
			return verifyResult{
				IsVerified: verified,
				ExtraData:  extraData,
				Error:      err,
			}, nil
		})

		res := r.(verifyResult)
		if res.IsVerified {
			return true, res.ExtraData, res.Error
		}

		errs = append(errs, res.Error)
	}

	return false, nil, errors.Join(errs...)
}

// doVerification checks whether |token| is valid for the given |registry|.
func doVerification(
	ctx context.Context,
	client *http.Client,
	registryInfo *registry.Info,
	authValue string,
) (bool, map[string]string, error) {
	// If the scheme is "unknown", default to HTTPS.
	if registryInfo.Scheme == registry.UnknownScheme {
		registryInfo.Scheme = registry.HttpsScheme
	}

	isVerified, extraData, err := registry.VerifyToken(ctx, client, registryInfo, authValue)
	if !isVerified {
		if err != nil {
			// If the scheme wasn't found when parsing we default to HTTPS, however, it might actually be HTTP.
			// This re-attempts the request with HTTP.
			//
			// e.g., `//registry.example.com/:_authToken=...`
			var tlsErr tls.RecordHeaderError
			if errors.As(err, &tlsErr) && registryInfo.Scheme == registry.HttpsScheme {
				r := *registryInfo
				r.Scheme = registryInfo.Scheme
				return doVerification(ctx, client, &r, authValue)
			}
		}
		return false, nil, nil
	}

	data := map[string]string{
		"registry_type":  registryInfo.Type.String(),
		"registry_url":   registryInfo.Uri,
		"rotation_guide": "https://howtorotate.com/docs/tutorials/npm/",
	}
	for k, v := range extraData {
		data[k] = v
	}
	return true, data, err
}
