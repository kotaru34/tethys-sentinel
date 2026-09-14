import { render } from "preact";
import { useCallback, useEffect, useState } from "preact/hooks";
import { APIError, establishSession, getJSON, postJSON } from "./api";
import type { Approval, ApprovalPage, AuditEvent, EmergencyState, Job, Overview, SessionInfo } from "./types";
import "./styles.css";

type RouteName = "overview" | "approvals" | "grants" | "jobs" | "audit" | "targets" | "context" | "security";
type ApprovalDecision = "deny" | "allow_once" | "allow_session";

const routes: Array<{ name: RouteName; label: string }> = [
  { name: "overview", label: "Overview" },
  { name: "approvals", label: "Approvals" },
  { name: "grants", label: "Grants" },
  { name: "jobs", label: "Jobs" },
  { name: "audit", label: "Audit" },
  { name: "targets", label: "Targets" },
  { name: "context", label: "Context" },
  { name: "security", label: "Security" },
];

function routeFromHash(): RouteName {
  const candidate = window.location.hash.replace(/^#\/?/, "") as RouteName;
  return routes.some((route) => route.name === candidate) ? candidate : "overview";
}

function useVisiblePolling(run: (signal: AbortSignal) => Promise<void>, intervalMs: number): void {
  useEffect(() => {
    let stopped = false;
    let timer = 0;
    let controller: AbortController | null = null;

    const schedule = () => {
      if (!stopped) {
        timer = window.setTimeout(cycle, intervalMs);
      }
    };

    const cycle = async () => {
      if (stopped) return;
      if (document.hidden) {
        schedule();
        return;
      }
      controller = new AbortController();
      try {
        await run(controller.signal);
      } finally {
        controller = null;
        schedule();
      }
    };

    const onVisibility = () => {
      if (!document.hidden && !controller) {
        window.clearTimeout(timer);
        void cycle();
      }
    };

    void cycle();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      controller?.abort();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [run, intervalMs]);
}

function formatTime(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function age(value: string): string {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return "unknown age";
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function errorText(error: unknown): string {
  if (error instanceof DOMException && error.name === "AbortError") return "";
  if (error instanceof Error) return error.message;
  return "unknown operator API error";
}

function Argv({ argv }: { argv: string[] }) {
  return (
    <ol class="argv" aria-label="Exact command arguments">
      {argv.map((argument, index) => (
        <li key={`${index}:${argument}`}>
          <span class="argv-index">argv[{index}]</span>
          <code>{argument}</code>
        </li>
      ))}
    </ol>
  );
}

function Badge({ children, tone = "neutral" }: { children: preact.ComponentChildren; tone?: "neutral" | "good" | "warn" | "bad" }) {
  return <span class={`badge badge-${tone}`}>{children}</span>;
}

interface ConfirmDialogProps {
  title: string;
  description: string;
  confirmLabel: string;
  destructive?: boolean;
  requireReason?: boolean;
  requiredPhrase?: string;
  busy: boolean;
  error?: string;
  onCancel: () => void;
  onConfirm: (reason: string) => Promise<void>;
}

function ConfirmDialog(props: ConfirmDialogProps) {
  const [reason, setReason] = useState("");
  const [phrase, setPhrase] = useState("");
  const phraseOK = !props.requiredPhrase || phrase === props.requiredPhrase;
  const reasonOK = !props.requireReason || reason.trim().length > 0;

  return (
    <div class="modal-backdrop" role="presentation">
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
        <h2 id="confirm-title">{props.title}</h2>
        <p>{props.description}</p>
        {props.requireReason && (
          <label class="field">
            <span>Reason</span>
            <textarea value={reason} onInput={(event) => setReason(event.currentTarget.value)} rows={3} disabled={props.busy} autofocus />
          </label>
        )}
        {props.requiredPhrase && (
          <label class="field">
            <span>Type <code>{props.requiredPhrase}</code> to confirm</span>
            <input value={phrase} onInput={(event) => setPhrase(event.currentTarget.value)} disabled={props.busy} autocomplete="off" />
          </label>
        )}
        {props.error && <p class="inline-error" role="alert">{props.error}</p>}
        <div class="modal-actions">
          <button class="button button-secondary" type="button" onClick={props.onCancel} disabled={props.busy}>Cancel</button>
          <button
            class={`button ${props.destructive ? "button-danger" : "button-primary"}`}
            type="button"
            disabled={props.busy || !phraseOK || !reasonOK}
            onClick={() => void props.onConfirm(reason.trim())}
          >
            {props.busy ? "Waiting for Control…" : props.confirmLabel}
          </button>
        </div>
      </section>
    </div>
  );
}

function AuthorityBanner({ overview, error }: { overview: Overview | null; error: string }) {
  if (error || !overview) {
    return (
      <div class="authority-banner authority-unknown" role="status">
        <strong>AUTHORITY STATE UNKNOWN</strong>
        <span>Operator data is stale or unavailable. Do not treat any previous enabled state as current.</span>
      </div>
    );
  }
  if (overview.authority.disabled) {
    return (
      <div class="authority-banner authority-disabled" role="status">
        <strong>AI AUTHORITY DISABLED</strong>
        <span>Epoch {overview.authority.epoch} · {overview.authority.reason || "no reason recorded"}</span>
      </div>
    );
  }
  return (
    <div class="authority-banner authority-enabled" role="status">
      <strong>AI AUTHORITY ENABLED</strong>
      <span>Epoch {overview.authority.epoch} · last changed {formatTime(overview.authority.updated_at)}</span>
    </div>
  );
}

function OverviewPage({ overview, error, lastFresh }: { overview: Overview | null; error: string; lastFresh: string }) {
  if (!overview) {
    return <StateMessage title="Overview unavailable" detail={error || "Waiting for the first authoritative read…"} bad={Boolean(error)} />;
  }

  const activeJobs = overview.counts.jobs.staged + overview.counts.jobs.pending + overview.counts.jobs.claimed + overview.counts.jobs.running;
  return (
    <section class="page">
      <header class="page-header">
        <div>
          <p class="eyebrow">Live supervision</p>
          <h1>Overview</h1>
        </div>
        <span class={`freshness ${error ? "freshness-stale" : ""}`}>{error ? "STALE" : `fresh ${formatTime(lastFresh)}`}</span>
      </header>
      {error && <p class="inline-error" role="alert">Refresh failed: {error}</p>}

      <div class="metrics">
        <Metric label="Pending approvals" value={overview.counts.pending_approvals} href="#/approvals" tone={overview.counts.pending_approvals > 0 ? "warn" : "neutral"} />
        <Metric label="Active grants" value={overview.counts.active_grants} href="#/grants" />
        <Metric label="Active jobs" value={activeJobs} href="#/jobs" tone={overview.counts.jobs.running > 0 ? "good" : "neutral"} />
        <Metric label="Failed jobs" value={overview.counts.jobs.failed} href="#/jobs" tone={overview.counts.jobs.failed > 0 ? "bad" : "neutral"} />
      </div>

      <div class="split-grid">
        <section class="panel">
          <div class="panel-heading">
            <h2>Recent failures</h2>
            <a href="#/jobs">All jobs</a>
          </div>
          {overview.recent_failures.length === 0 ? <p class="empty">No recent failed jobs.</p> : overview.recent_failures.map((job) => <JobFailure key={job.id} job={job} />)}
        </section>
        <section class="panel">
          <div class="panel-heading">
            <h2>Recent audit</h2>
            <a href="#/audit">Audit log</a>
          </div>
          {overview.recent_audit.length === 0 ? <p class="empty">No recent audit events.</p> : overview.recent_audit.map((event) => <AuditRow key={event.id} event={event} />)}
        </section>
      </div>
    </section>
  );
}

function Metric({ label, value, href, tone = "neutral" }: { label: string; value: number; href: string; tone?: "neutral" | "good" | "warn" | "bad" }) {
  return (
    <a class={`metric metric-${tone}`} href={href}>
      <span>{label}</span>
      <strong>{value}</strong>
    </a>
  );
}

function JobFailure({ job }: { job: Job }) {
  return (
    <article class="compact-row">
      <div class="compact-main">
        <div class="row-title"><code>{job.id}</code> <Badge tone="bad">{job.result?.error_kind || job.status}</Badge></div>
        <div class="row-meta">{job.agent} → {job.target} · {formatTime(job.completed_at || job.created_at)}</div>
      </div>
      <Argv argv={job.argv} />
    </article>
  );
}

function AuditRow({ event }: { event: AuditEvent }) {
  return (
    <article class="compact-row">
      <div class="row-title"><span class="sequence">#{event.sequence}</span> <strong>{event.kind}</strong></div>
      <div class="row-meta">{event.actor || "—"} · {formatTime(event.timestamp)}</div>
      {event.reason && <p class="row-reason">{event.reason}</p>}
    </article>
  );
}

function ApprovalsPage() {
  const [page, setPage] = useState<ApprovalPage | null>(null);
  const [error, setError] = useState("");
  const [lastFresh, setLastFresh] = useState("");
  const [selected, setSelected] = useState<{ approval: Approval; decision: ApprovalDecision } | null>(null);
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState("");

  const refresh = useCallback(async (signal: AbortSignal) => {
    try {
      const result = await getJSON<ApprovalPage>("/api/v1/approvals?status=pending&limit=100", signal);
      setPage(result);
      setError("");
      setLastFresh(new Date().toISOString());
    } catch (err) {
      const text = errorText(err);
      if (text) setError(text);
    }
  }, []);

  useVisiblePolling(refresh, 1000);

  const decide = async () => {
    if (!selected) return;
    setBusy(true);
    setMutationError("");
    try {
      await postJSON<Approval>(`/api/v1/approvals/${encodeURIComponent(selected.approval.id)}/decision`, { decision: selected.decision });
      setSelected(null);
      await refresh(new AbortController().signal);
    } catch (err) {
      const text = errorText(err);
      setMutationError(err instanceof APIError && err.status === 409 ? `Approval changed elsewhere: ${text}. Refreshing authoritative state.` : text);
      if (err instanceof APIError && err.status === 409) {
        await refresh(new AbortController().signal);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="page">
      <header class="page-header">
        <div><p class="eyebrow">Human gate</p><h1>Approvals</h1></div>
        <span class={`freshness ${error ? "freshness-stale" : ""}`}>{error ? "STALE" : `fresh ${formatTime(lastFresh)}`}</span>
      </header>
      {error && <p class="inline-error" role="alert">Approval queue refresh failed: {error}</p>}
      {!page ? <StateMessage title="Approval queue unavailable" detail={error || "Loading…"} bad={Boolean(error)} /> : page.items.length === 0 ? <StateMessage title="No pending approvals" detail="Control reports an empty pending queue." /> : (
        <div class="approval-list">
          {page.items.map((approval) => (
            <article class="approval-card" key={approval.id}>
              <div class="approval-topline">
                <div>
                  <span class="age">{age(approval.created_at)}</span>
                  <h2>{approval.agent} <span class="arrow">→</span> {approval.target}</h2>
                </div>
                <div class="badges"><Badge tone={approval.risk_level === "high" || approval.risk_level === "critical" ? "bad" : "warn"}>{approval.risk_level}</Badge><Badge>{approval.category}</Badge></div>
              </div>
              <Argv argv={approval.argv} />
              <div class="approval-reasons">
                <div><span>Agent reason</span><p>{approval.agent_reason || "No agent reason supplied."}</p></div>
                <div><span>Sentinel policy</span><p>{approval.risk_reason || "No additional policy reason supplied."}</p></div>
              </div>
              <dl class="facts">
                <div><dt>Grant</dt><dd><code>{approval.grant_id}</code></dd></div>
                <div><dt>Approval</dt><dd><code>{approval.id}</code></dd></div>
                <div><dt>Scope</dt><dd><code>{approval.scope_key}</code></dd></div>
              </dl>
              {!approval.session_approval_allowed && <p class="one-shot-note">One-shot only: Sentinel policy does not permit reusable session approval for this category.</p>}
              <div class="approval-actions">
                <button class="button button-secondary" type="button" onClick={() => { setMutationError(""); setSelected({ approval, decision: "deny" }); }}>Deny</button>
                <button class="button button-primary" type="button" onClick={() => { setMutationError(""); setSelected({ approval, decision: "allow_once" }); }}>Allow once</button>
                {approval.session_approval_allowed && <button class="button button-primary" type="button" onClick={() => { setMutationError(""); setSelected({ approval, decision: "allow_session" }); }}>Allow this session</button>}
              </div>
            </article>
          ))}
        </div>
      )}
      {selected && (
        <ConfirmDialog
          title={`${selected.decision === "deny" ? "Deny" : selected.decision === "allow_once" ? "Allow once" : "Allow this session"}: ${selected.approval.agent}`}
          description={`Approval ${selected.approval.id} for target ${selected.approval.target}. Control remains authoritative until it confirms this decision.`}
          confirmLabel={selected.decision === "deny" ? "Deny request" : selected.decision === "allow_once" ? "Allow once" : "Allow session"}
          destructive={selected.decision === "deny"}
          busy={busy}
          error={mutationError}
          onCancel={() => !busy && setSelected(null)}
          onConfirm={decide}
        />
      )}
    </section>
  );
}

function SecurityPage({ onAuthorityChanged }: { onAuthorityChanged: () => Promise<void> }) {
  const [state, setState] = useState<EmergencyState | null>(null);
  const [error, setError] = useState("");
  const [lastFresh, setLastFresh] = useState("");
  const [enableOpen, setEnableOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState("");

  const refresh = useCallback(async (signal: AbortSignal) => {
    try {
      const result = await getJSON<EmergencyState>("/api/v1/emergency/state", signal);
      setState(result);
      setError("");
      setLastFresh(new Date().toISOString());
    } catch (err) {
      const text = errorText(err);
      if (text) setError(text);
    }
  }, []);

  useVisiblePolling(refresh, 1000);

  const enable = async (reason: string) => {
    setBusy(true);
    setMutationError("");
    try {
      const result = await postJSON<EmergencyState>("/api/v1/emergency/enable", { reason });
      setState(result);
      setLastFresh(new Date().toISOString());
      setEnableOpen(false);
      await onAuthorityChanged();
    } catch (err) {
      setMutationError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="page">
      <header class="page-header">
        <div><p class="eyebrow">Emergency authority</p><h1>Security</h1></div>
        <span class={`freshness ${error ? "freshness-stale" : ""}`}>{error ? "STALE" : `fresh ${formatTime(lastFresh)}`}</span>
      </header>
      {error && <p class="inline-error" role="alert">Emergency state refresh failed: {error}</p>}
      {!state ? <StateMessage title="Security state unavailable" detail={error || "Loading…"} bad={Boolean(error)} /> : (
        <div class="security-layout">
          <section class={`authority-card ${state.disabled ? "authority-card-disabled" : "authority-card-enabled"}`}>
            <p class="eyebrow">Current state</p>
            <h2>{state.disabled ? "AI access disabled" : "AI access enabled"}</h2>
            <dl class="facts facts-large">
              <div><dt>Epoch</dt><dd>{state.epoch}</dd></div>
              <div><dt>Last update</dt><dd>{formatTime(state.updated_at)}</dd></div>
              <div><dt>Reason</dt><dd>{state.reason || "No reason recorded."}</dd></div>
            </dl>
          </section>
          <section class="panel security-explanation">
            <h2>Epoch semantics</h2>
            <p>Re-enabling AI access does not revive capabilities from an older security epoch. Old-epoch grants remain stale permanently.</p>
            {state.disabled ? (
              <button class="button button-primary" type="button" onClick={() => { setMutationError(""); setEnableOpen(true); }}>Enable AI access</button>
            ) : (
              <p class="empty">AI access is already enabled. Global revoke remains available in the header.</p>
            )}
          </section>
        </div>
      )}
      {enableOpen && (
        <ConfirmDialog
          title="Enable AI access"
          description="This increases active authority for grants in the current epoch. Older-epoch capabilities remain stale."
          confirmLabel="Enable AI access"
          requireReason
          requiredPhrase="ENABLE AI ACCESS"
          busy={busy}
          error={mutationError}
          onCancel={() => !busy && setEnableOpen(false)}
          onConfirm={enable}
        />
      )}
    </section>
  );
}

function StateMessage({ title, detail, bad = false }: { title: string; detail: string; bad?: boolean }) {
  return <div class={`state-message ${bad ? "state-message-bad" : ""}`}><h2>{title}</h2><p>{detail}</p></div>;
}

function PlaceholderPage({ route }: { route: RouteName }) {
  const label = routes.find((item) => item.name === route)?.label || route;
  return (
    <section class="page">
      <header class="page-header"><div><p class="eyebrow">dev.14 work in progress</p><h1>{label}</h1></div></header>
      <StateMessage title={`${label} screen is not in this checkpoint`} detail="The BFF route already exists. This browser view will be added before the dev.14 release and acceptance run." />
    </section>
  );
}

function App() {
  const [route, setRoute] = useState<RouteName>(routeFromHash());
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [sessionError, setSessionError] = useState("");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [overviewError, setOverviewError] = useState("");
  const [overviewFresh, setOverviewFresh] = useState("");
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [revokeBusy, setRevokeBusy] = useState(false);
  const [revokeError, setRevokeError] = useState("");

  useEffect(() => {
    const onHash = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHash);
    if (!window.location.hash) window.location.hash = "/overview";
    void establishSession().then((result) => { setSession(result); setSessionError(""); }).catch((err) => setSessionError(errorText(err)));
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const refreshOverview = useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await getJSON<Overview>("/api/v1/overview", signal);
      setOverview(result);
      setOverviewError("");
      setOverviewFresh(new Date().toISOString());
    } catch (err) {
      const text = errorText(err);
      if (text) setOverviewError(text);
    }
  }, []);

  const pollOverview = useCallback((signal: AbortSignal) => refreshOverview(signal), [refreshOverview]);
  useVisiblePolling(pollOverview, 1000);

  const revokeAll = async (reason: string) => {
    setRevokeBusy(true);
    setRevokeError("");
    try {
      await postJSON<EmergencyState>("/api/v1/emergency/revoke-all", { reason });
      setRevokeOpen(false);
      await refreshOverview();
    } catch (err) {
      setRevokeError(errorText(err));
    } finally {
      setRevokeBusy(false);
    }
  };

  const page = route === "overview" ? <OverviewPage overview={overview} error={overviewError} lastFresh={overviewFresh} />
    : route === "approvals" ? <ApprovalsPage />
    : route === "security" ? <SecurityPage onAuthorityChanged={() => refreshOverview()} />
    : <PlaceholderPage route={route} />;

  const revokeDisabled = Boolean(overview && !overviewError && overview.authority.disabled);

  return (
    <div class="app-shell">
      <header class="topbar">
        <a class="brand" href="#/overview" aria-label="Tethys Sentinel overview">
          <span class="brand-mark">T</span>
          <span><strong>Tethys Sentinel</strong><small>operator</small></span>
        </a>
        <div class="topbar-actions">
          {session ? <span class="operator-id" title={session.operator_identity}>mTLS operator · {session.operator_identity.slice(-12)}</span> : <span class="operator-id operator-id-bad">{sessionError ? "operator session error" : "establishing session…"}</span>}
          <button
            class="button button-danger emergency-button"
            type="button"
            disabled={revokeDisabled}
            onClick={() => { setRevokeError(""); setRevokeOpen(true); }}
          >
            {revokeDisabled ? "AI already disabled" : "REVOKE ALL"}
          </button>
        </div>
      </header>
      <AuthorityBanner overview={overview} error={overviewError} />
      {sessionError && <div class="session-error" role="alert">Operator session unavailable: {sessionError}. Mutations will fail closed.</div>}
      <div class="workspace">
        <nav class="sidebar" aria-label="Primary">
          {routes.map((item) => <a key={item.name} href={`#/${item.name}`} class={route === item.name ? "active" : ""}>{item.label}</a>)}
        </nav>
        <main>{page}</main>
      </div>
      {revokeOpen && (
        <ConfirmDialog
          title="REVOKE ALL AI authority"
          description="Control will advance the security epoch, disable global AI authority, invalidate every older capability permanently, and terminate running execution authority."
          confirmLabel="REVOKE ALL"
          destructive
          requireReason
          busy={revokeBusy}
          error={revokeError}
          onCancel={() => !revokeBusy && setRevokeOpen(false)}
          onConfirm={revokeAll}
        />
      )}
    </div>
  );
}

const root = document.getElementById("app");
if (!root) throw new Error("operator UI root element is missing");
render(<App />, root);
