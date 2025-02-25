package npm

// DetectorVersion assigns semantic meaning to detector "versions",
// as there are several independent formats.
type DetectorVersion int

const (
	/*
	 * TokenUuid: the original NPM token format, also implemented by tools like Nexus Repository 3.
	 *
	 * Examples:
	 * ```
	 * //registry.npmjs.org/:_authToken=a5f022f6-71b6-4402-82ca-f7842c12ede8
	 * echo //nexus.contoso.com/repository/npm-registry/:_authToken=NpmToken.47174bc4-45b5-4266-9ab9-3f930f03ed04 >> .npmrc
	 * ```
	 */
	TokenUuid DetectorVersion = iota + 1
	/*
	 * TokenNew: the new NPM token format announced by GitHub (https://github.blog/changelog/2021-09-23-npm-has-a-new-access-token-format/).
	 *
	 * Example: `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`
	 */
	TokenNew
	/*
	 * TokenGeneric: tokens used by third-party registry implementations (e.g., Artifactory, GitHub Artifacts).
	 *
	 * Examples:
	 * ```
	 * ```
	 */
	TokenGeneric
	// TODO: these are placeholders for future development.
	// https://yarnpkg.com/configuration/yarnrc#npmRegistries
	// TokenYarn
	// https://forum.unity.com/threads/npm-registry-authentication.836308/
	// https://github.com/openupm/openupm-cli/blob/0b70a3a6f2917888186706ca6838df2ea55ee066/docs/cmd-search.md?plain=1#L5
	// TokenUnity
)
