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
# (see below), never a stored password. `az acr build` (remote build,
# no local docker needed) was blocked on this subscription
# ("ACR Tasks requests ... are not permitted") — build locally and push
# instead. The push itself hit repeated transient TLS/connection resets
# through a local proxy on the first deployment (the ~380MB pip-install
# layer specifically, being the largest); retry, don't assume one
# failure means the registry or credentials are broken.
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
echo '      github-webhook-secret="$(grep "^GITHUB_WEBHOOK_SECRET=" .env | cut -d= -f2- | tr -d "\r\n")"'
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
az containerapp update --name "$API_APP_NAME" --resource-group "$RESOURCE_GROUP" \
    --image "$ACR_NAME.azurecr.io/codeguard:latest" \
    --set-env-vars \
        "ANTHROPIC_API_KEY=secretref:anthropic-api-key" \
        "DATABASE_URL=secretref:database-url" \
        "GITHUB_WEBHOOK_SECRET=secretref:github-webhook-secret" \
        "GITHUB_PRIVATE_KEY=secretref:github-private-key" \
        "GITHUB_APP_ID=$GITHUB_APP_ID" \
        "DB_SSLMODE=require" \
    --output none

# worker: DOES need a command override (python -m codeguard.worker.main,
# not the image's default). Same --args bug applies here, so this goes
# through --yaml instead of CLI flags, in one call that also sets the
# KEDA scale rule — a custom scale rule embedded directly in a create
# call was observed to hang ("Operation expired") the first few times;
# applying it as a separate update to an already-healthy app worked
# reliably, which is the order this script follows (image/command first
# as its own update, scale rule as a second update below).
WORKER_UPDATE_YAML=$(mktemp)
cat > "$WORKER_UPDATE_YAML" << YAML_EOF
properties:
  template:
    containers:
      - image: $ACR_NAME.azurecr.io/codeguard:latest
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
      minReplicas: 1
      maxReplicas: 1
YAML_EOF
az containerapp update --name "$WORKER_APP_NAME" --resource-group "$RESOURCE_GROUP" --yaml "$WORKER_UPDATE_YAML" --output none
rm -f "$WORKER_UPDATE_YAML"

# Scale-to-zero, applied once the worker is confirmed healthy on fixed
# scaling above — bundling this into the same update as the image/command
# switch was the specific combination that hung during the first
# deployment; kept as a separate step here even though it may not be
# strictly required every time.
WORKER_SCALE_YAML=$(mktemp)
cat > "$WORKER_SCALE_YAML" << 'YAML_EOF'
properties:
  template:
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
az containerapp update --name "$WORKER_APP_NAME" --resource-group "$RESOURCE_GROUP" --yaml "$WORKER_SCALE_YAML" --output none
rm -f "$WORKER_SCALE_YAML"

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
