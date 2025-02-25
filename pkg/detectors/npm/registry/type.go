package registry

// Type is used to indicate the registry implementation, if known.
// This is crucial for verification due to differences in behaviour.
type Type int

const (
	/*
	 * Others npm registries include:
	 * - https://github.com/verdaccio/verdaccio
	 * - https://coding.net/help/docs/ci/practice/artifacts/npm.html
	 * - https://www.privjs.com
	 * - https://npm.fontawesome.com
	 */
	other Type = iota
	npm
	artifactoryCloud
	artifactoryHosted
	nexusRepo2
	nexusRepo3
	gitlab      // TODO: create distinct type for self-hosted GitLab?
	githubCloud // TODO: self-hosted GitHub
	azure
	jetbrains
	googleArtifactRegistry
	gemfury
	awsCodeArtifact
)

func (t Type) String() string {
	return [...]string{
		"other",
		"npm",
		"artifactoryCloud",
		"artifactoryHosted",
		"nexusRepo2",
		"nexusRepo3",
		"gitlab",
		"githubCloud",
		"azure",
		"jetbrains",
		"googleArtifactRegistry",
		"gemfury",
		"awsCodeArtifact",
	}[t]
}
