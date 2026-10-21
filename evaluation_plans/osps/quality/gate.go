package quality

import (
	"strings"

	"github.com/ossf/pvtr-github-repo-scanner/data"
	"github.com/rhysd/actionlint"
)

// executedCheck is a check run from the last merged pull request. workflow is
// the workflow file that produced it, empty when GitHub Actions did not.
type executedCheck struct {
	name     string
	workflow string
}

// checkCoverage is the outcome of comparing executed checks to the required
// ones. missing checks are definitely not covered. uncertain checks belong to a
// workflow that could not be inspected, so a gate there cannot be ruled out.
type checkCoverage struct {
	missing   []string
	uncertain []string
	gates     []string
}

// executedStatusChecks returns the check runs on the default branch's last
// merged pull request that must be required status checks.
// Runs that concluded SKIPPED or NEUTRAL are left out: a job whose `if:` kept it
// from running on pull requests, such as a push-only release job, did no
// checking that a ruleset could require. Unfinished runs have no conclusion
// yet and are kept.
func executedStatusChecks(payload data.Payload) []executedCheck {
	var statusChecks []executedCheck
	for _, check := range payload.Repository.DefaultBranchRef.Target.Commit.AssociatedPullRequests.Nodes {
		for _, run := range check.StatusCheckRollup.Commit.CheckSuites.Nodes {
			for _, checkRun := range run.CheckRuns.Nodes {
				switch checkRun.Conclusion {
				case "SKIPPED", "NEUTRAL":
					continue
				}
				statusChecks = append(statusChecks, executedCheck{name: checkRun.Name, workflow: run.WorkflowRun.File.Path})
			}
		}
	}
	return statusChecks
}

// uncoveredChecks reports which executed checks the required contexts do not
// cover. A check counts as covered when its name is required, or when its
// workflow has a required gate job that needs it, directly or transitively,
// and still runs when a dependency fails. GitHub treats a skipped required
// check as passing, so a gate without such a condition proves nothing.
// A gate must also be able to fail on its dependencies, see failsOnNeeds.
func uncoveredChecks(payload data.Payload, required []string) checkCoverage {
	requiredSet := make(map[string]bool, len(required))
	for _, name := range required {
		requiredSet[name] = true
	}

	var unmatched []executedCheck
	for _, check := range executedStatusChecks(payload) {
		if !requiredSet[check.name] {
			unmatched = append(unmatched, check)
		}
	}

	var coverage checkCoverage
	if len(unmatched) == 0 {
		return coverage
	}

	workflows, loaded := loadGateWorkflows(payload, unmatched)
	seenGates := make(map[string]bool)
	for _, check := range unmatched {
		if check.workflow == "" {
			coverage.missing = append(coverage.missing, check.name)
			continue
		}
		info, ok := workflows[normalizeWorkflowPath(check.workflow)]
		if !loaded || !ok || info == nil {
			coverage.uncertain = append(coverage.uncertain, check.name)
			continue
		}
		gate := info.gateCovering(check.name, requiredSet)
		if gate == "" {
			coverage.missing = append(coverage.missing, check.name)
			continue
		}
		if !seenGates[gate] {
			seenGates[gate] = true
			coverage.gates = append(coverage.gates, gate)
		}
	}
	return coverage
}

func normalizeWorkflowPath(path string) string {
	return strings.TrimPrefix(strings.TrimPrefix(path, "./"), "/")
}

// loadGateWorkflows parses the workflow files behind the unmatched checks. A
// path maps to nil when its file is missing, truncated, or unparseable. The
// bool is false when the workflow files could not be fetched at all.
func loadGateWorkflows(payload data.Payload, unmatched []executedCheck) (map[string]*workflowGates, bool) {
	needed := make(map[string]bool)
	for _, check := range unmatched {
		if check.workflow != "" {
			needed[normalizeWorkflowPath(check.workflow)] = true
		}
	}
	parsed := make(map[string]*workflowGates, len(needed))
	if len(needed) == 0 {
		return parsed, true
	}

	files, err := payload.GetWorkflowFiles()
	if err != nil {
		return parsed, false
	}
	for _, file := range files {
		path := normalizeWorkflowPath(file.Path)
		if !needed[path] || file.Truncated {
			continue
		}
		workflow, err := actionlint.Parse([]byte(file.Content))
		if err != nil || workflow == nil {
			continue
		}
		parsed[path] = &workflowGates{workflow: workflow}
	}
	return parsed, true
}

type workflowGates struct {
	workflow *actionlint.Workflow
}

// gateCovering returns the name of a required gate job in this workflow that
// covers the named check, or "" when none does.
func (g *workflowGates) gateCovering(checkName string, required map[string]bool) string {
	for _, gate := range g.workflow.Jobs {
		gateName := jobCheckName(gate)
		if !required[gateName] || !isQualifyingGate(gate) {
			continue
		}
		for job := range g.needsClosure(gate) {
			if jobProducesCheck(job, checkName) {
				return gateName
			}
		}
	}
	return ""
}

// needsClosure returns every job the gate depends on, directly or through
// other jobs. Cycles are tolerated because actionlint reports them only as
// semantic errors.
func (g *workflowGates) needsClosure(gate *actionlint.Job) map[*actionlint.Job]bool {
	seen := make(map[*actionlint.Job]bool)
	queue := []*actionlint.Job{gate}
	for len(queue) > 0 {
		job := queue[0]
		queue = queue[1:]
		for _, need := range job.Needs {
			if need == nil {
				continue
			}
			dep, ok := g.workflow.Jobs[strings.ToLower(need.Value)]
			if !ok || seen[dep] {
				continue
			}
			seen[dep] = true
			queue = append(queue, dep)
		}
	}
	return seen
}

// jobCheckName is the check name GitHub reports for a plain job: its name, or
// its ID when unnamed.
func jobCheckName(job *actionlint.Job) string {
	if job.Name != nil && job.Name.Value != "" {
		return job.Name.Value
	}
	if job.ID != nil {
		return job.ID.Value
	}
	return ""
}

func isMatrixJob(job *actionlint.Job) bool {
	return job.Strategy != nil && job.Strategy.Matrix != nil
}

// isQualifyingGate reports whether the job runs even when a dependency fails
// and can then fail itself. Only a plain, non-matrix job with an exact
// condition qualifies, because the required context must match its single
// check name.
func isQualifyingGate(job *actionlint.Job) bool {
	if job.WorkflowCall != nil || isMatrixJob(job) || job.If == nil {
		return false
	}
	if strings.Contains(jobCheckName(job), "${{") || !failsOnNeeds(job) {
		return false
	}
	condition := strings.TrimSpace(job.If.Value)
	condition = strings.TrimPrefix(condition, "${{")
	condition = strings.TrimSuffix(condition, "}}")
	switch strings.TrimSpace(condition) {
	case "always()", "!cancelled()", "failure()":
		return true
	}
	return false
}

// jobProducesCheck reports whether a check run name can come from the job.
// Matrix jobs report "<name> (<values>)", reusable workflow calls report
// "<name> / <called job>", and a name holding an expression is matched by the
// literal text before it.
func jobProducesCheck(job *actionlint.Job, checkName string) bool {
	name := jobCheckName(job)
	if name == "" {
		return false
	}
	if before, _, found := strings.Cut(name, "${{"); found {
		return before != "" && strings.HasPrefix(checkName, before)
	}
	if job.WorkflowCall != nil {
		return checkName == name || strings.HasPrefix(checkName, name+" / ")
	}
	if isMatrixJob(job) {
		return checkName == name || strings.HasPrefix(checkName, name+" (")
	}
	return checkName == name
}

// failsOnNeeds reports whether the job can go red because of its dependencies:
// it must not ignore errors, and a step must read the `needs` context. A step
// that reads `needs` only in its condition still passes the check, so this is
// a heuristic that rejects the clear cases such as a gate that only echoes.
func failsOnNeeds(job *actionlint.Job) bool {
	if job.ContinueOnError != nil && (job.ContinueOnError.Expression != nil || job.ContinueOnError.Value) {
		return false
	}
	reads := func(s *actionlint.String) bool { return s != nil && strings.Contains(s.Value, "needs") }
	for _, step := range job.Steps {
		if step == nil {
			continue
		}
		if reads(step.If) {
			return true
		}
		switch exec := step.Exec.(type) {
		case *actionlint.ExecRun:
			if reads(exec.Run) {
				return true
			}
		case *actionlint.ExecAction:
			for _, input := range exec.Inputs {
				if input != nil && reads(input.Value) {
					return true
				}
			}
		}
	}
	return false
}
