# GitLab CI

Include the template from your `.gitlab-ci.yml`:

```yaml
include:
  - remote: https://raw.githubusercontent.com/amoghnellutla/breachgraph/v0/templates/gitlab-ci.yml
```

The `breachgraph` job runs on merge requests and on the default branch, with the Docker image
(every scanner at a pinned version).

- **On the default branch** it scans everything and keeps the report as a job artifact. That
  report is the base for merge requests.
- **On a merge request** it downloads the default branch's last report (with the job's own
  `CI_JOB_TOKEN`), compares with it, and rescans only the files that changed. Findings and attack
  paths that already exist on the default branch don't fail the merge request, and the result
  leads with the attack paths the change opens or closes.
- **The merge request note.** Add a project access token with the `api` scope (Settings >
  Access tokens, role Reporter or higher) as a masked CI/CD variable named
  `BREACHGRAPH_GITLAB_TOKEN`. The job then posts one note on the merge request and updates it on
  every pipeline, with the attack-path diagram (GitLab renders Mermaid). GitLab's `CI_JOB_TOKEN`
  can't write notes, which is why a token is needed.
- Gating findings also appear as failed tests in the merge request widget (JUnit), and the HTML
  report is a job artifact.

Pass more options with `BREACHGRAPH_ARGS`:

```yaml
breachgraph:
  variables:
    BREACHGRAPH_ARGS: "--fail-on P2"
```

Until the default branch has run the job once, merge requests get a full scan and no comparison.
