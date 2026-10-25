# REST fallback and JQL

Use only when the Atlassian MCP connector is unavailable. Variables come from the environment; none are printed or written to disk.

| Variable | Meaning |
|---|---|
| `JIRA_BASE_URL` | `https://vidlunnia.atlassian.net` |
| `JIRA_EMAIL` | Account email, used in `basic` mode |
| `JIRA_TOKEN` | API token (`basic`, Cloud) or personal access token (`bearer`, Data Center) |
| `JIRA_PROJECT_KEY` | `FREES` |
| `JIRA_AUTH_MODE` | `basic` or `bearer`; fail closed on any other value |

## Authentication

- `basic`: `Authorization: Basic base64(JIRA_EMAIL:JIRA_TOKEN)`.
- `bearer`: `Authorization: Bearer JIRA_TOKEN`.
- Build headers in memory, never echo them, never enable verbose HTTP tracing.

## Endpoints (REST API v3 on Cloud)

| Purpose | Call |
|---|---|
| Search | `GET /rest/api/3/search/jql?jql=<encoded>` |
| Create | `POST /rest/api/3/issue` |
| Update | `PUT /rest/api/3/issue/{key}` |
| List transitions | `GET /rest/api/3/issue/{key}/transitions` |
| Transition | `POST /rest/api/3/issue/{key}/transitions` with the discovered transition id |
| Comment | `POST /rest/api/3/issue/{key}/comment` |
| Link | `POST /rest/api/3/issueLink` with type `Blocks` |

Descriptions and comments on v3 use Atlassian Document Format.

## JQL

```text
project = FREES AND labels = "plan-<slug>"
project = FREES AND labels = "milestone-2" AND statusCategory != Done
project = FREES AND issuetype = Epic ORDER BY created
```

Create only when the first query returns zero issues; when it returns more than one, stop and report the duplicates.
