package data

// FindFile returns the repository path of the first of the given filenames found
// in the repository root or .github directory, matched case-insensitively. It
// reuses the REST contents fetched during Setup, so once .github has been probed
// it costs no additional API call. Returns "" when none of the names is present.
//
// It exists so evaluation steps in other packages can run deterministic
// filesystem fallbacks without reaching into RestData's unexported checkFile.
func (r *RestData) FindFile(names ...string) string {
	if r == nil {
		return ""
	}
	for _, name := range names {
		if path := r.checkFile(name); path != "" {
			return path
		}
	}
	return ""
}
