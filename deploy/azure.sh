#!/usr/bin/env bash
# Azure deployment for CodeGuard — api (1 fixed replica) + worker
# (scale-to-zero) Container Apps, Azure Database for PostgreSQL Flexible
# Server, Azure Container Registry. Written from the actual sequence
# that worked during the first live deployment (2026-09), including the
# real failures hit along the way — see the comments at each step
# before "fixing" something that looks wrong; it's probably there
# because the obvious approach failed once already.
#
# Run from the repo root, on the branch you want to ship (see the
# branch check below — this refuses to build from anything but
# BUILD_BRANCH, main by default, on purpose: this exact mistake
# happened once, mid-deployment, building v2 into what was meant to be
# a from-main image).
#
# Secrets: read live from your own .env and ./secrets/*.pem at the
# point each is needed — never hardcoded here, never echoed. You need
# ANTHROPIC_API_KEY and GITHUB_WEBHOOK_SECRET in .env, and the GitHub
# App's private key at ./secrets/codeguard.private-key.pem, before
# running the sections that need them.
#
# Idempotency: safe to re-run. Resource creation steps check for an
# existing resource first; nothing here deletes anything.

set -euo pipefail

# ---- config -----------------------------------------------------------
RESOURCE_GROUP="codeguard-prod"
LOCATION="westus"          # NOT eastus/eastus2/westus2 — this subscription
                            # had them "restricted from provisioning in this
                            # region" for Postgres Flexible Server specifically;
                            # westus was the first one that worked. Re-check
                            # with `az postgres flexible-server create --location X`
                            # if you ever need a different region — the CLI
                            # surfaces the restriction immediately, no resource
                            # is created on failure, so it's cheap to just try.
ACR_NAME="codeguardacr"
PG_SERVER_NAME="codeguard-pg"
PG_ADMIN_USER="codeguard_admin"
PG_DB_NAME="codeguard"
LOG_ANALYTICS_NAME="codeguard-logs"
ENVIRONMENT_NAME="codeguard-env"
API_APP_NAME="codeguard-api"
WORKER_APP_NAME="codeguard-worker"
GITHUB_APP_ID="4934663"

# Who may press the dashboard's "Run audit" button. A list of GitHub
# logins, comma separated — NOT a secret, so a plain value rather than a
# secretref: there is nothing to leak, and putting it in the secret store
# would make a list of usernames harder to read than the thing it gates.
#
# Declared here and passed on every deploy, rather than set once by hand.
# METRICS_AUTH_TOKEN taught us the difference: set manually it survived
# future deploys only because `--set-env-vars` happens to merge, i.e. by
# accident rather than by intent, and nothing in the script recorded that
# it was meant to exist. An undeclared env var is one a future deploy can
# silently drop, and dropping this one turns the button off with no error.
#
# Empty is the safe direction and matches the Settings default: nobody
# may trigger an audit. An audit clones a repository and spends this
# deployment's own Anthropic credit, so "unset" must mean "no one", never
# "everyone".
DASHBOARD_AUDIT_PRINCIPALS="${DASHBOARD_AUDIT_PRINCIPALS:-ashrithaumd}"
BUILD_BRANCH="main"        # the whole point of this script's existence
                            # per its own commit message: image builds
                            # come from main, not from a feature branch.

# ---- branch guard -------------------------------------------------------
current_branch="$(git rev-parse --abbrev-ref HEAD)"
if [ "$current_branch" != "$BUILD_BRANCH" ]; then
    echo "ERROR: on branch '$current_branch', expected '$BUILD_BRANCH'." >&2
    echo "Checkout $BUILD_BRANCH yourself (this script won't do it for you —" >&2
    echo "switching branches for you risks discarding uncommitted work)." >&2
    exit 1
fi

# ---- resource providers (one-time per subscription) --------------------
az provider register -n Microsoft.DBforPostgreSQL --wait
az provider register -n Microsoft.App --wait
az provider register -n Microsoft.OperationalInsights --wait
az provider register -n Microsoft.ContainerRegistry --wait

# ---- resource group ------------------------------------------------------
# Idempotency guard, same pattern as every other resource below — without
# it, a re-run against an already-existing group fails outright
# (InvalidResourceGroupLocation) if its recorded location metadata ever
# differs from $LOCATION, even though nothing would actually need to
# change: a resource group's own "location" is just metadata about where
# its management data lives, not a constraint on where child resources
# (Container Apps, Postgres) actually run.
if ! az group show --name "$RESOURCE_GROUP" --output none 2>/dev/null; then
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
fi

# ---- container registry --------------------------------------------------
if ! az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" --output none 2>/dev/null; then
    az acr create --resource-group "$RESOURCE_GROUP" --name "$ACR_NAME" --sku Basic --output none
fi
# Admin user stays OFF — both Container Apps pull via managed identity
# (see below), never a stored password. `az acr build` (remote build, no
# local docker needed) is blocked on this subscription; re-confirmed
# 2026-09-19 from Cloud Shell, so it is NOT a stale note and not a SKU
# limitation — it is subscription-level on the free tier:
#   (TasksOperationsNotAllowed) ACR Tasks requests for the registry
#   codeguardacr and 29ca79a0-... are not permitted.
# That leaves building locally and pushing, below. The push hit repeated
# transient TLS/connection resets through a local proxy on the first
# deployment (the ~380MB pip-install layer specifically, being the
# largest); retry, don't assume one failure means the registry or
# credentials are broken.
#
# SKIP_BUILD=1 skips this entirely and deploys whatever is already in the
# registry, for when the local Docker can't reach ACR at all — Docker
# Desktop 4.46.0 persists a proxy bypass (OverrideProxyExclude) in its
# settings but never passes it to the daemon, so *.azurecr.io can't be
# excluded from the proxy and the push cannot be made to work locally.
# .github/workflows/build-push.yml does the build on GitHub's runners
# instead. Nothing below trusts CI blindly: the digest assertion further
# down proves the registry's :latest is actually this commit's image
# before anything is deployed.
if [ "${SKIP_BUILD:-}" = "1" ]; then
    echo "SKIP_BUILD=1: not building locally — deploying the image already in $ACR_NAME."
else
    az acr login --name "$ACR_NAME"
    docker build -t "$ACR_NAME.azurecr.io/codeguard:latest" .
    push_ok=false
    for attempt in $(seq 1 15); do
        if docker push "$ACR_NAME.azurecr.io/codeguard:latest" 2>&1 | tee /tmp/acr_push.log | grep -q "^latest: digest"; then
            push_ok=true
            break
        fi
        echo "push attempt $attempt failed, retrying..." >&2
        sleep 3
    done
    if [ "$push_ok" != true ]; then
        echo "ERROR: image push never succeeded after 15 attempts — see /tmp/acr_push.log" >&2
        exit 1
    fi
fi

# ---- postgres flexible server ---------------------------------------------
if ! az postgres flexible-server show --resource-group "$RESOURCE_GROUP" --name "$PG_SERVER_NAME" --output none 2>/dev/null; then
    echo "Postgres server doesn't exist yet — create it with a password you generate"
    echo "yourself (never through this script — see the project's own incident notes"
    echo "on why a secret should never be materialized into a command or a file):"
    echo
    echo '  az postgres flexible-server create --resource-group '"$RESOURCE_GROUP"' \'
    echo '    --name '"$PG_SERVER_NAME"' --location '"$LOCATION"' \'
    echo '    --admin-user '"$PG_ADMIN_USER"' --admin-password "$(openssl rand -base64 24)" \'
    echo '    --sku-name Standard_B1ms --tier Burstable --storage-size 32 --version 16 \'
    echo '    --public-access 0.0.0.0'
    echo
    echo "Note: --public-access 0.0.0.0 (a single 0.0.0.0, not a range) is Azure's"
    echo "special value for 'allow Azure services only' — do NOT use the full"
    echo "0.0.0.0-255.255.255.255 range, which opens the server to the entire"
    echo "internet (a real mistake made and then fixed during the first deployment)."
    echo
    echo "Then re-run this script."
    exit 1
fi

# pgcrypto must be explicitly allow-listed before migrations/001_jobs.sql's
# CREATE EXTENSION pgcrypto can succeed — Azure Flexible Server rejects
# unlisted extensions with FeatureNotSupported, which otherwise surfaces
# as a confusing worker/api crash-loop on first boot, not an obvious
# "add this Azure setting" error.
az postgres flexible-server parameter set \
    --resource-group "$RESOURCE_GROUP" --server-name "$PG_SERVER_NAME" \
    --name azure.extensions --value pgcrypto --output none

az postgres flexible-server db create \
    --resource-group "$RESOURCE_GROUP" --server-name "$PG_SERVER_NAME" \
    --database-name "$PG_DB_NAME" --output none 2>/dev/null || true

# ---- log analytics + container apps environment ---------------------------
if ! az monitor log-analytics workspace show --resource-group "$RESOURCE_GROUP" --workspace-name "$LOG_ANALYTICS_NAME" --output none 2>/dev/null; then
    az monitor log-analytics workspace create \
        --resource-group "$RESOURCE_GROUP" --workspace-name "$LOG_ANALYTICS_NAME" \
        --location "$LOCATION" --output none
fi

if ! az containerapp env show --name "$ENVIRONMENT_NAME" --resource-group "$RESOURCE_GROUP" --output none 2>/dev/null; then
    WS_ID=$(az monitor log-analytics workspace show --resource-group "$RESOURCE_GROUP" --workspace-name "$LOG_ANALYTICS_NAME" --query customerId -o tsv)
    WS_KEY=$(az monitor log-analytics workspace get-shared-keys --resource-group "$RESOURCE_GROUP" --workspace-name "$LOG_ANALYTICS_NAME" --query primarySharedKey -o tsv)
    az containerapp env create \
        --name "$ENVIRONMENT_NAME" --resource-group "$RESOURCE_GROUP" --location "$LOCATION" \
        --logs-workspace-id "$WS_ID" --logs-workspace-key "$WS_KEY" --output none
fi

# ---- bootstrap-then-switch pattern for both apps ---------------------------
# A brand-new Container App can't use managed-identity ACR pull from its
# very first revision — the identity's principalId doesn't exist until
# AFTER the app resource is created, so there's nothing yet for AcrPull
# to be granted to, and the platform's own retry/backoff around this
# gap was observed to time out ("Operation expired") rather than fail
# fast, on both attempts to do it in one step during the first
# deployment. The reliable sequence: bootstrap with a public image that
# needs no registry credential at all, THEN assign identity, grant the
# role, switch the registry to identity auth, and only THEN point the
# image at the real one.
_bootstrap_and_wire_identity() {
    local app_name="$1"
    local extra_create_args="$2"

    if ! az containerapp show --name "$app_name" --resource-group "$RESOURCE_GROUP" --output none 2>/dev/null; then
        az containerapp create \
            --name "$app_name" --resource-group "$RESOURCE_GROUP" --environment "$ENVIRONMENT_NAME" \
            --image mcr.microsoft.com/k8se/quickstart:latest \
            --cpu 0.25 --memory 0.5Gi \
            $extra_create_args --output none

        local principal_id
        principal_id=$(az containerapp identity assign --name "$app_name" --resource-group "$RESOURCE_GROUP" --system-assigned --query principalId -o tsv)

        local acr_id
        acr_id=$(az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" --query id -o tsv)
        # MSYS_NO_PATHCONV: git-bash on Windows mangles /subscriptions/...-shaped
        # arguments as if they were POSIX paths needing translation, silently
        # corrupting the scope and producing an opaque "MissingSubscription"
        # error — only reproduces on Windows git-bash, not native Linux/macOS
        # shells, but costs nothing to set unconditionally.
        MSYS_NO_PATHCONV=1 az role assignment create \
            --assignee "$principal_id" --role AcrPull --scope "$acr_id" --output none

        az containerapp registry set --name "$app_name" --resource-group "$RESOURCE_GROUP" \
            --server "$ACR_NAME.azurecr.io" --identity system --output none
    fi
}

_bootstrap_and_wire_identity "$API_APP_NAME" "--min-replicas 1 --max-replicas 1 --ingress external --target-port 8000"
_bootstrap_and_wire_identity "$WORKER_APP_NAME" "--min-replicas 1 --max-replicas 1"

# ---- secrets (read live from your own files, never stored here) -----------
# Each app's secrets need to exist before the final image/config update
# below references them via secretRef. Re-run these any time a value
# rotates — `secret set` is safe to call repeatedly.
DATABASE_URL_PROMPT='postgresql://'"$PG_ADMIN_USER"':<YOUR_PG_PASSWORD>@'"$PG_SERVER_NAME"'.postgres.database.azure.com:5432/'"$PG_DB_NAME"'?sslmode=require'
echo "Set each app's secrets now (reads from .env / ./secrets/ in your own shell, not this script):"
echo
echo '  az containerapp secret set --name '"$API_APP_NAME"' --resource-group '"$RESOURCE_GROUP"' \'
echo '    --secrets anthropic-api-key="$(grep "^ANTHROPIC_API_KEY=" .env | cut -d= -f2- | tr -d "\r\n")" \'
echo '      database-url="'"$DATABASE_URL_PROMPT"'" \'
echo '      github-webhook-secret="$(grep "^GITHUB_WEBHOOK_SECRET=" .env | cut -d= -f2- | tr -d "\r\n")" \'
echo '      metrics-auth-token="$(openssl rand -hex 32)"'
echo
echo "  metrics-auth-token gates /metrics, which is excluded from EasyAuth and was"
echo "  therefore publicly readable until it was set. api/main.py only WARNS when it"
echo "  is missing (the endpoint fails open so local compose keeps working), so an"
echo "  unset value is silent from the outside -- the api answers 200 and looks"
echo "  healthy while serving queue depth and webhook counts to anyone who asks."
echo "  Generate it here rather than reading .env: nothing else needs a copy."
echo "  The worker does NOT need it -- its :9000/metrics is prometheus_client, which"
echo "  this token does not gate, and it has no ingress to be reached through."
echo
echo "  For the multi-line private key, use a YAML update (a single CLI --secrets"
echo "  value containing embedded newlines was observed to get corrupted in transit"
echo "  during the first deployment — 'Could not parse the provided public key' at"
echo "  runtime, even though the source .pem file itself was valid):"
echo
echo '  WORKER_YAML=$(mktemp)'
echo '  cat > "$WORKER_YAML" << YAML_EOF'
echo 'properties:'
echo '  configuration:'
echo '    secrets:'
echo '      - name: github-private-key'
echo '        value: |'
echo '$(sed "s/^/          /" ./secrets/codeguard.private-key.pem)'
echo 'YAML_EOF'
echo '  az containerapp update --name '"$API_APP_NAME"' --resource-group '"$RESOURCE_GROUP"' --yaml "$WORKER_YAML"'
echo '  az containerapp update --name '"$WORKER_APP_NAME"' --resource-group '"$RESOURCE_GROUP"' --yaml "$WORKER_YAML"'
echo '  shred -u "$WORKER_YAML" 2>/dev/null || rm -f "$WORKER_YAML"'
echo

# Safety checkpoint by default — do NOT remove or auto-pipe past this in a
# non-interactive run, that defeats the whole point of a human confirming
# secrets are actually set before the real image/config below goes live.
# SKIP_SECRETS_PROMPT=1 exists ONLY for a re-run where secrets are already
# known-good (e.g. a redeploy right after a rotation already verified
# working in production) — it skips only this pause, never the printed
# secret-setting instructions above, which still show every run.
if [ "${SKIP_SECRETS_PROMPT:-}" != "1" ]; then
    read -rp "Press enter once secrets are set on both apps to continue with the real image + config..." _
fi

# ---- switch both apps to the real image + real command/env ----------------
# api: no --command/--args override needed at all — the Dockerfile's own
# CMD already runs uvicorn correctly. (An earlier attempt to pass
# `--command uvicorn --args "app,--host,..."` as a single comma-joined
# string, and separately as multiple quoted --args values, both failed:
# this CLI extension's --args parsing does not reliably accept more than
# one value, contradicting its own --help example. Simplest fix: don't
# override it — the image already knows how to start itself.)
#
# --revision-suffix, keyed to the deployed commit, not a timestamp: without
# an explicit suffix, `update` with the exact same --image/--set-env-vars
# values as last time is indistinguishable to Container Apps from a no-op
# (it diffs the requested spec, not whatever a mutable :latest tag now
# points at in the registry) — confirmed live: a real image rebuild+push
# left the api revision from 2026-09-16 running, unchanged, through several
# subsequent `update` calls. A timestamp suffix would force a fresh
# revision on every run regardless of whether the code changed, piling up
# junk revisions; the commit SHA only changes when the code does, and the
# revision name itself then tells you which commit is actually live.
#
# Deployed by DIGEST, not the :latest tag: this is what makes the
# same-SHA/different-digest case (a rebuild with no commit — a base image
# update, a dependency resolving differently, a retried push) detectable
# at all. With a floating tag, there's nothing to compare against; pinned
# by digest, the existing revision's own spec already says exactly what
# it's running, no separate tracking needed.
API_REVISION_SUFFIX="$(git rev-parse --short HEAD)"
API_REVISION_NAME="${API_APP_NAME}--${API_REVISION_SUFFIX}"
LATEST_DIGEST="$(az acr repository show --name "$ACR_NAME" --image codeguard:latest --query digest -o tsv)"

# Provenance check, only meaningful when CI did the build. When this
# script builds (the else branch above), :latest came from this very
# working tree seconds ago and provenance holds by construction. When CI
# built it, it does not: :latest is a floating tag recording nothing
# about which commit produced it, and HEAD here can easily be behind (or
# ahead of) whatever CI last pushed. Deploying that under a revision
# named for THIS commit would stamp the wrong provenance onto the
# revision — the same class of untracked mismatch the drift guard below
# refuses, arriving from a different direction.
#
# CI also pushes an immutable :sha-<7> tag. If this commit's tag and
# :latest don't resolve to the same digest, :latest belongs to some other
# commit: stop rather than deploy it under this one's name.
#
# 7 chars sliced from the full SHA, not `git rev-parse --short`: git's
# abbreviation length depends on the repo's object count and CI checks
# out shallow, so --short can disagree across the two clones. The slice
# is identical on both sides by construction. (API_REVISION_SUFFIX above
# keeps using --short — it names revisions that already exist, and is
# independent of this tag.)
if [ "${SKIP_BUILD:-}" = "1" ]; then
    COMMIT_TAG="sha-$(git rev-parse HEAD | cut -c1-7)"
    COMMIT_DIGEST="$(az acr repository show --name "$ACR_NAME" --image "codeguard:$COMMIT_TAG" --query digest -o tsv 2>/dev/null || true)"
    if [ -z "$COMMIT_DIGEST" ]; then
        echo "==============================================================" >&2
        echo "ERROR: no $COMMIT_TAG tag in $ACR_NAME — CI has not built this commit." >&2
        echo "  Push it to main, or run the build-push workflow against it, and wait" >&2
        echo "  for that run to finish before deploying." >&2
        echo "==============================================================" >&2
        exit 1
    fi
    if [ "$COMMIT_DIGEST" != "$LATEST_DIGEST" ]; then
        echo "==============================================================" >&2
        echo "ERROR: :latest in $ACR_NAME is not this commit's image." >&2
        echo "  HEAD ($COMMIT_TAG): $COMMIT_DIGEST" >&2
        echo "  :latest:            $LATEST_DIGEST" >&2
        echo "  A later commit's build has moved :latest, or this checkout is stale." >&2
        echo "  Check out the commit you mean to deploy, or re-run CI on this one." >&2
        echo "==============================================================" >&2
        exit 1
    fi
    echo "Provenance OK: :latest and $COMMIT_TAG are the same digest ($LATEST_DIGEST)."
fi

if az containerapp revision show --name "$API_APP_NAME" --resource-group "$RESOURCE_GROUP" --revision "$API_REVISION_NAME" --output none 2>/dev/null; then
    EXISTING_IMAGE="$(az containerapp revision show --name "$API_APP_NAME" --resource-group "$RESOURCE_GROUP" --revision "$API_REVISION_NAME" --query "properties.template.containers[0].image" -o tsv)"
    EXISTING_DIGEST="${EXISTING_IMAGE#*@}"
    if [ "$EXISTING_DIGEST" = "$LATEST_DIGEST" ]; then
        echo "Revision $API_REVISION_NAME already exists and runs the current image digest ($LATEST_DIGEST) — skipping."
    elif [ "${ALLOW_DIGEST_DRIFT:-}" != "1" ]; then
        # Same commit, different build output — this is NOT a case to
        # silently fold into an ordinary deploy or auto-resolve: it means
        # something changed that the git history doesn't explain (base
        # image drift, an unpinned dependency resolving differently, a
        # retried push that landed a different layer). Stop and let a
        # human decide, rather than leave a decision like that in a log
        # nobody read.
        echo "==============================================================" >&2
        echo "ERROR: same commit ($API_REVISION_SUFFIX) but a DIFFERENT image digest than what's currently deployed under that name." >&2
        echo "  currently deployed: $EXISTING_DIGEST" >&2
        echo "  now at :latest:     $LATEST_DIGEST" >&2
        echo "  This means something changed without a commit — investigate before deploying it blind." >&2
        echo "  Re-run with ALLOW_DIGEST_DRIFT=1 if you've confirmed this new digest should go out." >&2
        echo "==============================================================" >&2
        exit 1
    else
        echo "ALLOW_DIGEST_DRIFT=1: deploying the new digest under a distinct revision name (same commit, different build)."
        API_REVISION_SUFFIX="${API_REVISION_SUFFIX}-$(echo "$LATEST_DIGEST" | cut -d: -f2 | cut -c1-8)"
        az containerapp update --name "$API_APP_NAME" --resource-group "$RESOURCE_GROUP" \
            --image "$ACR_NAME.azurecr.io/codeguard@$LATEST_DIGEST" \
            --revision-suffix "$API_REVISION_SUFFIX" \
            --set-env-vars \
                "ANTHROPIC_API_KEY=secretref:anthropic-api-key" \
                "DATABASE_URL=secretref:database-url" \
                "GITHUB_WEBHOOK_SECRET=secretref:github-webhook-secret" \
                "GITHUB_PRIVATE_KEY=secretref:github-private-key" \
                "GITHUB_APP_ID=$GITHUB_APP_ID" \
                "DB_SSLMODE=require" \
                "METRICS_AUTH_TOKEN=secretref:metrics-auth-token" \
                "DASHBOARD_AUDIT_PRINCIPALS=$DASHBOARD_AUDIT_PRINCIPALS" \
            --output none
    fi
else
    az containerapp update --name "$API_APP_NAME" --resource-group "$RESOURCE_GROUP" \
        --image "$ACR_NAME.azurecr.io/codeguard@$LATEST_DIGEST" \
        --revision-suffix "$API_REVISION_SUFFIX" \
        --set-env-vars \
            "ANTHROPIC_API_KEY=secretref:anthropic-api-key" \
            "DATABASE_URL=secretref:database-url" \
            "GITHUB_WEBHOOK_SECRET=secretref:github-webhook-secret" \
            "GITHUB_PRIVATE_KEY=secretref:github-private-key" \
            "GITHUB_APP_ID=$GITHUB_APP_ID" \
            "DB_SSLMODE=require" \
            "METRICS_AUTH_TOKEN=secretref:metrics-auth-token" \
            "DASHBOARD_AUDIT_PRINCIPALS=$DASHBOARD_AUDIT_PRINCIPALS" \
        --output none
fi

# worker: DOES need a command override (python -m codeguard.worker.main,
# not the image's default). Same --args bug applies here, so this goes
# through --yaml instead of CLI flags.
#
# ONE update, not two. This used to switch the image first and apply the
# KEDA scale rule second, because a scale rule in the original CREATE
# call had hung ("Operation expired") during the first deployment. But
# two updates mint two revisions, and the first of them is a live,
# auto-numbered replica that polls the queue and can claim a job moments
# before the second update deactivates it. That is not hypothetical: on
# 2026-09-22 revision --0000012 claimed a review and was terminated
# 0.23s after its semgrep subprocess died, producing a review with no
# semgrep coverage at all. Collapsing to a single update removes the
# transient revision, so no replica exists purely to be superseded.
#
# The hang that motivated the split was on a CREATE, not an update, and
# the app always exists by this point (_bootstrap_and_wire_identity ran
# above), so the case it guarded against cannot arise here.
#
# Deployed by DIGEST under a commit-named revision, exactly as the api is
# above and for the same reasons. It used to deploy the floating :latest
# tag under an auto-numbered revision, which meant the provenance check
# further up guarded only half the deployment: "which commit is the
# worker running?" had no answer on the worker side, and a :latest that
# had since moved would have been picked up silently on the next
# unrelated update. The worker is the half that actually runs reviews.
WORKER_IMAGE="$ACR_NAME.azurecr.io/codeguard@$LATEST_DIGEST"
WORKER_REVISION_NAME="${WORKER_APP_NAME}--${API_REVISION_SUFFIX}"
WORKER_EXISTING_IMAGE="$(az containerapp revision show --name "$WORKER_APP_NAME" --resource-group "$RESOURCE_GROUP" \
    --revision "$WORKER_REVISION_NAME" --query "properties.template.containers[0].image" -o tsv 2>/dev/null || true)"

# Reuses API_REVISION_SUFFIX rather than re-deriving it, so both apps
# always carry the same revision name for one deploy — including in the
# ALLOW_DIGEST_DRIFT case, where that suffix has already been extended
# with the digest prefix. That's also what makes the else branch safe:
# a drifted digest can only arrive here under a suffix that has already
# been made distinct, so this never tries to recreate an existing
# revision name with different contents.
if [ "$WORKER_EXISTING_IMAGE" = "$WORKER_IMAGE" ]; then
    echo "Revision $WORKER_REVISION_NAME already exists and runs the current image digest ($LATEST_DIGEST) — skipping."
else
WORKER_UPDATE_YAML=$(mktemp)
cat > "$WORKER_UPDATE_YAML" << YAML_EOF
properties:
  template:
    revisionSuffix: $API_REVISION_SUFFIX
    containers:
      - image: $WORKER_IMAGE
        name: $WORKER_APP_NAME
        command: ["python"]
        args: ["-m", "codeguard.worker.main"]
        resources:
          cpu: 0.25
          memory: 0.5Gi
        env:
          - name: ANTHROPIC_API_KEY
            secretRef: anthropic-api-key
          - name: DATABASE_URL
            secretRef: database-url
          - name: GITHUB_APP_ID
            value: "$GITHUB_APP_ID"
          - name: GITHUB_PRIVATE_KEY
            secretRef: github-private-key
          - name: DB_SSLMODE
            value: require
    scale:
      minReplicas: 0
      maxReplicas: 3
      rules:
        - name: postgres-pending-jobs
          custom:
            type: postgresql
            metadata:
              query: "SELECT count(*) FROM jobs WHERE status='pending'"
              targetQueryValue: "1"
              activationTargetQueryValue: "0"
              connectionFromEnv: DATABASE_URL
YAML_EOF
az containerapp update --name "$WORKER_APP_NAME" --resource-group "$RESOURCE_GROUP" --yaml "$WORKER_UPDATE_YAML" --output none
rm -f "$WORKER_UPDATE_YAML"

fi

# ACR admin user should stay disabled — both apps pull via managed
# identity only. If this ever errors saying admin is already disabled,
# that's fine, it means an earlier run already did this.
az acr update --name "$ACR_NAME" --admin-enabled false --output none

echo
echo "Done. Remaining manual steps this script can't do for you:"
echo "  - Point the GitHub App's Webhook URL at:"
echo "    https://$(az containerapp show --name "$API_APP_NAME" --resource-group "$RESOURCE_GROUP" --query properties.configuration.ingress.fqdn -o tsv)/webhook"
echo "  - Add the Azure api's public FQDN to observability/prometheus.yml's"
echo "    codeguard-api-azure job if you haven't already, and restart the local"
echo "    Prometheus container to pick it up."
