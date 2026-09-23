# Running CodeGuard as a GitHub App

This is the full deployment: a webhook receiver, a Postgres queue and a worker. If you only want to
scan a repo once, `codeguard audit` needs none of it — see the README quickstart.

You need a deployment reachable over HTTPS before the App can be pointed at it. Either run
[docs/self-host.md](self-host.md) first, or use a tunnel for local development (step 6).

## 1. Create the App

At **github.com/settings/apps** → **New GitHub App**. Name it, set a homepage URL (anything), and
leave the Webhook URL blank for now — you will fill it in at step 6.

## 2. Set permissions

Under **Permissions & events** → **Repository permissions**:

| Permission | Access | Why |
|---|---|---|
| **Contents** | Read | Fetch changed files at `head_sha`, and `.codeguard.yml` from the base branch |
| **Pull requests** | Read & write | Post the review and its inline comments |
| **Checks** | Read & write | Create the Check Run a branch-protection rule gates on |
| **Issues** | Read & write | Only if you use `codeguard audit --post-issue` |

Adding **Checks** after the App is already installed makes GitHub prompt existing installations to
approve the new permission. Until someone approves it, check runs fail and reviews still post.

## 3. Subscribe to events

Under **Subscribe to events**:

- **Pull request** — triggers a review on `opened` and `synchronize`.
- **Pull request review comment** — powers the feedback loop.
- **Issue comment** — the other half of the feedback loop.

Only `opened` and `synchronize` start a review. Every push to an open pull request is its own
review, with its own cost.

## 4. Generate a webhook secret and a private key

Set a **Webhook secret** to a random string you generate yourself. Every delivery's
`X-Hub-Signature-256` is verified against it, and a delivery that fails verification is rejected
before anything is enqueued.

Then **Generate a private key** and download the `.pem`. This is the only copy — GitHub does not
show it again.

Do not paste either value into a shell command, a config file in the repo, or a chat window. They
go in `.env` locally, or in your platform's secret store when deployed.

## 5. Note the App ID

On the App's **General** page. This is `GITHUB_APP_ID`.

## 6. Point the Webhook URL at your deployment

`https://<your-deployment>/webhook`.

For local development, forward deliveries with a tunnel and use the tunnel URL here instead:

```bash
npx smee-client --url "$SMEE_URL" --target http://localhost:8000/webhook
```

The same field switches between the tunnel and the deployed URL with no code change.

## 7. Configure the deployment

The App path needs these beyond `ANTHROPIC_API_KEY`:

```bash
GITHUB_APP_ID=123456
GITHUB_WEBHOOK_SECRET=<the secret from step 4>
GITHUB_PRIVATE_KEY_PATH=./secrets/your-app.private-key.pem   # local: a mounted file
# or
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."     # where secrets are env-vars only
DATABASE_URL=postgresql://...                                 # the queue lives here
```

`GITHUB_PRIVATE_KEY` takes precedence when both are set. Use it on platforms where secrets are
environment variables rather than mounted files, such as Azure Container Apps.

## 8. Install it on a repository

From the App's settings page → **Install App** → choose the account and the repositories. Start
with one repository you do not mind being commented on.

## 9. Open a pull request

Push a branch with a Python change and open a PR. Within a minute or two you should see a review
with inline comments and a **CodeGuard Review** check.

If nothing happens, work down this list:

- **App settings → Advanced → Recent Deliveries.** This shows whether GitHub sent the webhook and
  what your endpoint answered. A `401 invalid signature` means `GITHUB_WEBHOOK_SECRET` does not
  match. A timeout or connection error means the URL is wrong or unreachable.
- **The review only runs on Python files.** Lockfiles, generated files, docs, vendored code and
  every non-Python file are filtered at ingest. A PR touching only Markdown produces nothing.
- **Check the worker logs**, not the api's. The api only verifies and enqueues; everything else
  happens in the worker.

## 10. Gate merges on it (optional)

Repository **Settings → Branches → Branch protection rules → Require status checks to pass**, and
select **CodeGuard Review**.

The check fails when a confirmed finding is at or above `gate_threshold`, which defaults to
`critical`. Adding a `.codeguard.yml` to the base branch changes that — see
[docs/self-host.md](self-host.md#codeguardyml).

Make the check required only once you have watched a few reviews and are satisfied with what it
confirms. It is the one setting that can block a colleague's merge.
