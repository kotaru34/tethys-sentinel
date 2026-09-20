import { render, type ComponentChildren } from "preact";
import { useCallback, useEffect, useMemo, useState } from "preact/hooks";
import { APIError, establishSession, getJSON, postJSON } from "./api";
import type { Approval, ApprovalPage, AuditEvent, EmergencyState, Job, Overview, SessionInfo } from "./types";
import type {
  AuditPage,
  ContextView,
  GrantPage,
  GrantView,
  HistoryScope,
  IssueGrantResponse,
  JobPage,
  Permissions,
  TargetPage,
  TargetView,
} from "./operator-types";
import "./styles.css";
import "./extended.css";

type RouteName = "overview" | "approvals" | "grants" | "jobs" | "audit" | "targets" | "context" | "security";
type ApprovalDecision = "deny" | "allow_once" | "allow_session";
type Tone = "neutral" | "good" | "warn" | "bad";

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

const emptyPermissions = (): Permissions => ({
  exec: true,
  shell: false,
  upload: false,
  download: false,
  history_read: false,
  notes_read: false,
  notes_write: false,
});

const emptyHistory = (): HistoryScope => ({
  current_session: false,
  previous_sessions: false,
  other_agents: false,
  include_output: false,
});

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
      if (!stopped) timer = window.setTimeout(cycle, intervalMs);
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

function Badge({ children, tone = "neutral" }: { children: ComponentChildren; tone?: Tone }) {
  return <span class={`badge badge-${tone}`}>{children}</span>;
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

function StateMessage({ title, detail, bad = false }: { title: string; detail: string; bad?: boolean }) {
  return <div class={`state-message ${bad ? "state-message-bad" : ""}`}><h2>{title}</h2><p>{detail}</p></div>;
}

function Freshness({ error, value }: { error: string; value: string }) {
  return <span class={`freshness ${error ? "freshness-stale" : ""}`}>{error ? "STALE" : value ? `fresh ${formatTime(value)}` : "loading"}</span>;
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

function Metric({ label, value, href, tone = "neutral" }: { label: string; value: number; href: string; tone?: Tone }) {
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

function OverviewPage({ overview, error, lastFresh }: { overview: Overview | null; error: string; lastFresh: string }) {
  if (!overview) return <section class="page"><StateMessage title="Overview unavailable" detail={error || "Waiting for the first authoritative read…"} bad={Boolean(error)} /></section>;
  const activeJobs = overview.counts.jobs.staged + overview.counts.jobs.pending + overview.counts.jobs.claimed + overview.counts.jobs.running;
  return (
    <section class="page">
      <header class="page-header">
        <div><p class="eyebrow">Live supervision</p><h1>Overview</h1></div>
        <Freshness error={error} value={lastFresh} />
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
          <div class="panel-heading"><h2>Recent failures</h2><a href="#/jobs">All jobs</a></div>
          {overview.recent_failures.length === 0 ? <p class="empty">No recent failed jobs.</p> : overview.recent_failures.map((job) => <JobFailure key={job.id} job={job} />)}
        </section>
        <section class="panel">
          <div class="panel-heading"><h2>Recent audit</h2><a href="#/audit">Audit log</a></div>
          {overview.recent_audit.length === 0 ? <p class="empty">No recent audit events.</p> : overview.recent_audit.map((event) => <AuditRow key={event.id} event={event} />)}
        </section>
      </div>
    </section>
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
      if (err instanceof APIError && err.status === 409) await refresh(new AbortController().signal);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="page">
      <header class="page-header"><div><p class="eyebrow">Human gate</p><h1>Approvals</h1></div><Freshness error={error} value={lastFresh} /></header>
      {error && <p class="inline-error" role="alert">Approval queue refresh failed: {error}</p>}
      {!page ? <StateMessage title="Approval queue unavailable" detail={error || "Loading…"} bad={Boolean(error)} /> : page.items.length === 0 ? <StateMessage title="No pending approvals" detail="Control reports an empty pending queue." /> : (
        <div class="approval-list">
          {page.items.map((approval) => (
            <article class="approval-card" key={approval.id}>
              <div class="approval-topline">
                <div><span class="age">{age(approval.created_at)}</span><h2>{approval.agent} <span class="arrow">→</span> {approval.target}</h2></div>
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

function grantTone(state: GrantView["state"]): Tone {
  if (state === "active") return "good";
  if (state === "disabled" || state === "stale_epoch") return "warn";
  return state === "revoked" ? "bad" : "neutral";
}

function enabledPermissions(permissions: Permissions): string[] {
  return Object.entries(permissions).filter(([, enabled]) => enabled).map(([name]) => name);
}

function GrantsPage() {
  const [page, setPage] = useState<GrantPage | null>(null);
  const [targets, setTargets] = useState<TargetView[]>([]);
  const [error, setError] = useState("");
  const [lastFresh, setLastFresh] = useState("");
  const [filter, setFilter] = useState("all");
  const [agent, setAgent] = useState("");
  const [purpose, setPurpose] = useState("");
  const [selectedTargets, setSelectedTargets] = useState<string[]>([]);
  const [permissions, setPermissions] = useState<Permissions>(emptyPermissions);
  const [history, setHistory] = useState<HistoryScope>(emptyHistory);
  const [ttl, setTTL] = useState(900);
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState("");
  const [reveal, setReveal] = useState<IssueGrantResponse | null>(null);
  const [copyState, setCopyState] = useState("");
  const [revoke, setRevoke] = useState<GrantView | null>(null);
  const [revokeBusy, setRevokeBusy] = useState(false);
  const [revokeError, setRevokeError] = useState("");

  const refresh = useCallback(async (signal: AbortSignal) => {
    try {
      const [grants, targetPage] = await Promise.all([
        getJSON<GrantPage>("/api/v1/grants?limit=200", signal),
        getJSON<TargetPage>("/api/v1/targets", signal),
      ]);
      setPage(grants);
      setTargets(targetPage.items);
      setError("");
      setLastFresh(new Date().toISOString());
    } catch (err) {
      const text = errorText(err);
      if (text) setError(text);
    }
  }, []);
  useVisiblePolling(refresh, 5000);

  const visible = useMemo(() => (page?.items || []).filter((grant) => filter === "all" || grant.state === filter), [page, filter]);

  const toggleTarget = (name: string) => {
    setSelectedTargets((current) => current.includes(name) ? current.filter((item) => item !== name) : [...current, name]);
  };
  const setPermission = (name: keyof Permissions, checked: boolean) => setPermissions((current) => ({ ...current, [name]: checked }));
  const setHistoryFlag = (name: keyof HistoryScope, checked: boolean) => setHistory((current) => ({ ...current, [name]: checked }));

  const issue = async (event: Event) => {
    event.preventDefault();
    setIssueError("");
    if (!agent.trim() || !purpose.trim() || selectedTargets.length === 0) {
      setIssueError("Agent, purpose and at least one target are required.");
      return;
    }
    if (ttl < 30 || ttl > 28800) {
      setIssueError("TTL must be between 30 and 28800 seconds.");
      return;
    }
    setIssuing(true);
    try {
      const result = await postJSON<IssueGrantResponse>("/api/v1/grants", {
        agent: agent.trim(),
        purpose: purpose.trim(),
        targets: selectedTargets,
        permissions,
        history,
        ttl_seconds: ttl,
      });
      setReveal(result);
      setCopyState("");
      setAgent("");
      setPurpose("");
      setSelectedTargets([]);
      setPermissions(emptyPermissions());
      setHistory(emptyHistory());
      await refresh(new AbortController().signal);
    } catch (err) {
      setIssueError(errorText(err));
    } finally {
      setIssuing(false);
    }
  };

  const revokeGrant = async () => {
    if (!revoke) return;
    setRevokeBusy(true);
    setRevokeError("");
    try {
      await postJSON<void>(`/api/v1/grants/${encodeURIComponent(revoke.id)}/revoke`, {});
      setRevoke(null);
      await refresh(new AbortController().signal);
    } catch (err) {
      setRevokeError(errorText(err));
    } finally {
      setRevokeBusy(false);
    }
  };

  const copyCapability = async () => {
    if (!reveal) return;
    try {
      await navigator.clipboard.writeText(reveal.token);
      setCopyState("Copied to clipboard.");
    } catch {
      setCopyState("Clipboard write failed; select and copy the capability manually.");
    }
  };

  return (
    <section class="page">
      <header class="page-header"><div><p class="eyebrow">Capability authority</p><h1>Grants</h1></div><Freshness error={error} value={lastFresh} /></header>
      {error && <p class="inline-error" role="alert">Grant state refresh failed: {error}</p>}
      <div class="grant-layout">
        <section class="panel issue-panel">
          <div class="panel-heading"><h2>Issue grant</h2><span class="muted-note">Capability is revealed once.</span></div>
          <form onSubmit={issue}>
            <div class="form-grid">
              <label class="field"><span>Agent</span><input value={agent} onInput={(event) => setAgent(event.currentTarget.value)} autocomplete="off" /></label>
              <label class="field"><span>TTL seconds</span><input type="number" min="30" max="28800" value={ttl} onInput={(event) => setTTL(Number(event.currentTarget.value))} /></label>
            </div>
            <label class="field"><span>Purpose</span><textarea rows={3} value={purpose} onInput={(event) => setPurpose(event.currentTarget.value)} /></label>
            <fieldset class="check-group"><legend>Targets</legend>
              {targets.length === 0 ? <p class="empty">No protected targets are currently exposed.</p> : targets.map((target) => (
                <label class="check-row" key={target.name}><input type="checkbox" checked={selectedTargets.includes(target.name)} onChange={(event) => toggleTarget(target.name)} /><span><strong>{target.name}</strong><small>{target.address}</small></span></label>
              ))}
            </fieldset>
            <fieldset class="check-group"><legend>Permissions</legend>
              {(["exec", "shell", "upload", "download", "history_read", "notes_read", "notes_write"] as Array<keyof Permissions>).map((name) => (
                <label class="check-row compact-check" key={name}><input type="checkbox" checked={permissions[name]} onChange={(event) => setPermission(name, event.currentTarget.checked)} /><span>{name}</span></label>
              ))}
            </fieldset>
            <fieldset class="check-group"><legend>History scope</legend>
              {(["current_session", "previous_sessions", "other_agents", "include_output"] as Array<keyof HistoryScope>).map((name) => (
                <label class="check-row compact-check" key={name}><input type="checkbox" checked={history[name]} onChange={(event) => setHistoryFlag(name, event.currentTarget.checked)} /><span>{name}</span></label>
              ))}
            </fieldset>
            {issueError && <p class="inline-error" role="alert">{issueError}</p>}
            <button class="button button-primary" type="submit" disabled={issuing || targets.length === 0}>{issuing ? "Issuing…" : "Issue grant"}</button>
          </form>
        </section>
        <section class="panel grant-list-panel">
          <div class="panel-heading"><h2>Recent grants</h2><label class="mini-filter">State <select value={filter} onChange={(event) => setFilter(event.currentTarget.value)}><option value="all">all</option><option value="active">active</option><option value="disabled">disabled</option><option value="stale_epoch">stale epoch</option><option value="revoked">revoked</option><option value="expired">expired</option></select></label></div>
          {!page ? <p class="empty">Loading grants…</p> : visible.length === 0 ? <p class="empty">No grants match this state.</p> : visible.map((grant) => (
            <article class="grant-row" key={grant.id}>
              <div class="grant-row-main">
                <div class="row-title"><strong>{grant.agent}</strong><Badge tone={grantTone(grant.state)}>{grant.state}</Badge></div>
                <p class="row-reason">{grant.purpose}</p>
                <div class="row-meta">targets {grant.targets.join(", ")} · epoch {grant.security_epoch} · expires {formatTime(grant.expires_at)}</div>
                <div class="chip-line">{enabledPermissions(grant.permissions).map((name) => <span class="chip" key={name}>{name}</span>)}</div>
                <details class="technical"><summary>Technical details</summary><dl class="facts"><div><dt>Grant ID</dt><dd><code>{grant.id}</code></dd></div><div><dt>Issued</dt><dd>{formatTime(grant.issued_at)}</dd></div><div><dt>Revoked</dt><dd>{formatTime(grant.revoked_at)}</dd></div></dl><pre>{JSON.stringify({ history: grant.history, permissions: grant.permissions }, null, 2)}</pre></details>
              </div>
              {grant.state === "active" || grant.state === "disabled" ? <button class="button button-danger" type="button" onClick={() => { setRevokeError(""); setRevoke(grant); }}>Revoke</button> : null}
            </article>
          ))}
        </section>
      </div>
      {revoke && <ConfirmDialog title={`Revoke grant for ${revoke.agent}`} description={`Revoke grant ${revoke.id}. This reduces authority immediately and may cancel or terminate execution that still depends on this grant.`} confirmLabel="Revoke grant" destructive busy={revokeBusy} error={revokeError} onCancel={() => !revokeBusy && setRevoke(null)} onConfirm={revokeGrant} />}
      {reveal && (
        <div class="modal-backdrop" role="presentation">
          <section class="modal capability-modal" role="dialog" aria-modal="true" aria-labelledby="capability-title">
            <p class="eyebrow">One-time reveal</p><h2 id="capability-title">New capability issued</h2>
            <p>Copy this capability now. Sentinel persists only its hash and cannot retrieve this plaintext token later. Closing this dialog forgets it from the browser application state.</p>
            <div class="capability-token"><code>{reveal.token}</code></div>
            <dl class="facts"><div><dt>Grant</dt><dd><code>{reveal.grant.id}</code></dd></div><div><dt>Agent</dt><dd>{reveal.grant.agent}</dd></div><div><dt>Expires</dt><dd>{formatTime(reveal.grant.expires_at)}</dd></div></dl>
            {copyState && <p class="muted-note">{copyState}</p>}
            <div class="modal-actions"><button class="button button-secondary" type="button" onClick={() => { setReveal(null); setCopyState(""); }}>Dismiss &amp; forget</button><button class="button button-primary" type="button" onClick={() => void copyCapability()}>Copy capability</button></div>
          </section>
        </div>
      )}
    </section>
  );
}

function jobTone(status: string): Tone {
  if (status === "running" || status === "succeeded") return "good";
  if (status === "failed" || status === "canceled") return "bad";
  if (status === "expired") return "warn";
  return "neutral";
}

function JobsPage() {
  const [page, setPage] = useState<JobPage | null>(null);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [error, setError] = useState("");
  const [lastFresh, setLastFresh] = useState("");
  const [status, setStatus] = useState("all");
  const [query, setQuery] = useState("");
  const [selectedID, setSelectedID] = useState("");

  const refresh = useCallback(async (signal: AbortSignal) => {
    try {
      const [jobs, events] = await Promise.all([
        getJSON<JobPage>("/api/v1/jobs?limit=200", signal),
        getJSON<AuditPage>("/api/v1/audit?limit=200", signal),
      ]);
      setPage(jobs);
      setAudit(events.items);
      setError("");
      setLastFresh(new Date().toISOString());
    } catch (err) {
      const text = errorText(err);
      if (text) setError(text);
    }
  }, []);
  useVisiblePolling(refresh, 1000);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (page?.items || []).filter((job) => {
      if (status !== "all" && job.status !== status) return false;
      if (!needle) return true;
      return [job.id, job.request_id, job.grant_id, job.agent, job.target, job.risk_category || "", job.scope_key || "", ...job.argv].some((value) => value.toLowerCase().includes(needle));
    });
  }, [page, status, query]);
  const selected = page?.items.find((job) => job.id === selectedID) || null;
  const linkedAudit = selected ? audit.filter((event) => event.metadata && Object.values(event.metadata).some((value) => value === selected.id)) : [];

  return (
    <section class="page">
      <header class="page-header"><div><p class="eyebrow">Execution lifecycle</p><h1>Jobs</h1></div><Freshness error={error} value={lastFresh} /></header>
      {error && <p class="inline-error" role="alert">Job refresh failed: {error}</p>}
      <div class="filter-bar"><label>Search <input value={query} onInput={(event) => setQuery(event.currentTarget.value)} placeholder="job, request, grant, agent, target, risk…" /></label><label>Status <select value={status} onChange={(event) => setStatus(event.currentTarget.value)}><option value="all">all</option>{["staged", "pending", "claimed", "running", "succeeded", "failed", "canceled", "expired"].map((value) => <option value={value} key={value}>{value}</option>)}</select></label></div>
      <div class="master-detail">
        <section class="panel dense-list">
          {!page ? <p class="empty">Loading jobs…</p> : filtered.length === 0 ? <p class="empty">No jobs match these filters.</p> : filtered.map((job) => (
            <button class={`list-button ${selectedID === job.id ? "selected" : ""}`} type="button" key={job.id} onClick={() => setSelectedID(job.id)}>
              <span><strong>{job.agent}</strong> → {job.target}</span><Badge tone={jobTone(job.status)}>{job.status}</Badge><small><code>{job.id}</code> · {formatTime(job.created_at)}</small>
            </button>
          ))}
        </section>
        <section class="panel detail-panel">
          {!selected ? <StateMessage title="Select a job" detail="Choose a job to inspect immutable binding, lifecycle and terminal result." /> : (
            <>
              <div class="panel-heading"><div><p class="eyebrow">Job detail</p><h2><code>{selected.id}</code></h2></div><Badge tone={jobTone(selected.status)}>{selected.status}</Badge></div>
              <dl class="facts detail-facts"><div><dt>Request</dt><dd><code>{selected.request_id}</code></dd></div><div><dt>Grant</dt><dd><code>{selected.grant_id}</code></dd></div><div><dt>Agent</dt><dd>{selected.agent}</dd></div><div><dt>Target</dt><dd>{selected.target}</dd></div><div><dt>Risk</dt><dd>{selected.risk_category || "—"}</dd></div><div><dt>Scope</dt><dd><code>{selected.scope_key || "—"}</code></dd></div></dl>
              <h3>Exact argv</h3><Argv argv={selected.argv} />
              <h3>Lifecycle</h3><div class="timeline"><TimelineItem label="Created / staged" time={selected.created_at} active /><TimelineItem label="Claimed" time={selected.claimed_at} active={Boolean(selected.claimed_at)} /><TimelineItem label="Started" time={selected.started_at} active={Boolean(selected.started_at)} /><TimelineItem label={`Terminal: ${selected.status}`} time={selected.completed_at} active={Boolean(selected.completed_at)} /></div>
              {selected.result && <section class="result-box"><h3>Result</h3><dl class="facts"><div><dt>Success</dt><dd>{String(selected.result.success)}</dd></div><div><dt>Exit code</dt><dd>{selected.result.exit_code}</dd></div><div><dt>Error kind</dt><dd>{selected.result.error_kind || "—"}</dd></div><div><dt>Output SHA-256</dt><dd><code>{selected.result.output_sha256 || "—"}</code></dd></div></dl></section>}
              <h3>Explicit audit references</h3>{linkedAudit.length === 0 ? <p class="empty">No exposed audit metadata explicitly references this job ID.</p> : linkedAudit.map((event) => <AuditRow key={event.id} event={event} />)}
              <details class="technical"><summary>Technical binding</summary><pre>{JSON.stringify({ command_sha256: selected.command_sha256, approval_id: selected.approval_id, created_at: selected.created_at, expires_at: selected.expires_at, claimed_at: selected.claimed_at, started_at: selected.started_at, completed_at: selected.completed_at }, null, 2)}</pre></details>
            </>
          )}
        </section>
      </div>
    </section>
  );
}

function TimelineItem({ label, time, active }: { label: string; time?: string; active: boolean }) {
  return <div class={`timeline-item ${active ? "timeline-active" : ""}`}><span class="timeline-dot" /><div><strong>{label}</strong><small>{formatTime(time)}</small></div></div>;
}

function AuditPageView() {
  const [page, setPage] = useState<AuditPage | null>(null);
  const [error, setError] = useState("");
  const [lastFresh, setLastFresh] = useState("");
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("all");

  const refresh = useCallback(async (signal: AbortSignal) => {
    try {
      const result = await getJSON<AuditPage>("/api/v1/audit?limit=200", signal);
      setPage(result);
      setError("");
      setLastFresh(new Date().toISOString());
    } catch (err) {
      const text = errorText(err);
      if (text) setError(text);
    }
  }, []);
  useVisiblePolling(refresh, 5000);

  const kinds = useMemo(() => Array.from(new Set((page?.items || []).map((event) => event.kind))).sort(), [page]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (page?.items || []).filter((event) => {
      if (kind !== "all" && event.kind !== kind) return false;
      if (!needle) return true;
      const metadata = event.metadata ? Object.entries(event.metadata).flat() : [];
      return [event.kind, event.actor || "", event.grant_id || "", event.target || "", event.approval_id || "", event.decision || "", event.category || "", event.reason || "", ...metadata].some((value) => value.toLowerCase().includes(needle));
    });
  }, [page, query, kind]);

  return (
    <section class="page">
      <header class="page-header"><div><p class="eyebrow">Verified read path</p><h1>Audit</h1></div><Freshness error={error} value={lastFresh} /></header>
      {error && <p class="inline-error" role="alert">Audit refresh failed: {error}</p>}
      <div class="filter-bar"><label>Search <input value={query} onInput={(event) => setQuery(event.currentTarget.value)} placeholder="actor, target, grant, decision, metadata…" /></label><label>Kind <select value={kind} onChange={(event) => setKind(event.currentTarget.value)}><option value="all">all</option>{kinds.map((value) => <option value={value} key={value}>{value}</option>)}</select></label></div>
      <section class="panel audit-table-wrap">
        {!page ? <p class="empty">Loading audit trail…</p> : filtered.length === 0 ? <p class="empty">No audit events match these filters.</p> : (
          <div class="audit-table">
            {filtered.map((event) => (
              <article class="audit-entry" key={event.id}>
                <div class="audit-sequence">#{event.sequence}</div>
                <div class="audit-body"><div class="row-title"><strong>{event.kind}</strong>{event.decision && <Badge tone={event.decision === "deny" ? "bad" : "neutral"}>{event.decision}</Badge>}</div><div class="row-meta">{formatTime(event.timestamp)} · actor {event.actor || "—"}{event.target ? ` · target ${event.target}` : ""}</div>{event.reason && <p class="row-reason">{event.reason}</p>}{event.argv && event.argv.length > 0 && <Argv argv={event.argv} />}<details class="technical"><summary>Technical chain / metadata</summary><pre>{JSON.stringify({ id: event.id, grant_id: event.grant_id, approval_id: event.approval_id, category: event.category, scope_key: event.scope_key, metadata: event.metadata, prev_hash: event.prev_hash, hash: event.hash }, null, 2)}</pre></details></div>
              </article>
            ))}
          </div>
        )}
      </section>
    </section>
  );
}

function TargetsPage() {
  const [page, setPage] = useState<TargetPage | null>(null);
  const [error, setError] = useState("");
  const [lastFresh, setLastFresh] = useState("");
  const refresh = useCallback(async (signal: AbortSignal) => {
    try {
      const result = await getJSON<TargetPage>("/api/v1/targets", signal);
      setPage(result);
      setError("");
      setLastFresh(new Date().toISOString());
    } catch (err) {
      const text = errorText(err);
      if (text) setError(text);
    }
  }, []);
  useVisiblePolling(refresh, 10000);

  return (
    <section class="page">
      <header class="page-header"><div><p class="eyebrow">Protected inventory · read only</p><h1>Targets</h1></div><Freshness error={error} value={lastFresh} /></header>
      <p class="boundary-note">This surface cannot add, edit or delete SSH targets. Reachability and pinned host keys remain operator-owned configuration outside the browser.</p>
      {error && <p class="inline-error" role="alert">Target inventory refresh failed: {error}</p>}
      {!page ? <StateMessage title="Target inventory unavailable" detail={error || "Loading…"} bad={Boolean(error)} /> : <div class="target-grid">{page.items.map((target) => (
        <article class="target-card" key={target.name}><div class="panel-heading"><h2>{target.name}</h2><Badge>read only</Badge></div><dl class="facts facts-large"><div><dt>Address</dt><dd><code>{target.address}</code></dd></div><div><dt>SSH user</dt><dd><code>{target.user}</code></dd></div><div><dt>Host key algorithm</dt><dd><code>{target.host_key_algorithm}</code></dd></div><div><dt>SHA-256 fingerprint</dt><dd><code>{target.host_key_fingerprint}</code></dd></div></dl><details class="technical"><summary>Raw pinned public key</summary><pre>{target.host_key}</pre></details></article>
      ))}</div>}
    </section>
  );
}

function ContextPage() {
  const [context, setContext] = useState<ContextView | null>(null);
  const [error, setError] = useState("");
  const [lastFresh, setLastFresh] = useState("");
  const refresh = useCallback(async (signal: AbortSignal) => {
    try {
      const result = await getJSON<ContextView>("/api/v1/context", signal);
      setContext(result);
      setError("");
      setLastFresh(new Date().toISOString());
    } catch (err) {
      const text = errorText(err);
      if (text) setError(text);
    }
  }, []);
  useVisiblePolling(refresh, 10000);

  return (
    <section class="page">
      <header class="page-header"><div><p class="eyebrow">Authoritative context · read only</p><h1>Context</h1></div><Freshness error={error} value={lastFresh} /></header>
      <p class="boundary-note">Trust-0 is authority-bearing input. This UI intentionally exposes no route to edit policy, instructions, hosts or runbooks.</p>
      {error && <p class="inline-error" role="alert">Context refresh failed: {error}</p>}
      {!context ? <StateMessage title="Authoritative context unavailable" detail={error || "Loading…"} bad={Boolean(error)} /> : (
        <>
          <div class="context-summary"><Badge tone="warn">{context.trust_level}</Badge><span>snapshot <code>{context.version}</code></span></div>
          <div class="split-grid context-docs"><section class="panel"><h2>Policy</h2><pre class="context-text">{context.policy}</pre></section><section class="panel"><h2>Instructions</h2><pre class="context-text">{context.instructions}</pre></section></div>
          <section class="section-block"><div class="panel-heading"><h2>Inventory hosts</h2><span class="muted-note">{context.hosts.length} entries</span></div><div class="target-grid">{context.hosts.map((host) => <article class="target-card" key={host.name}><h2>{host.name}</h2><dl class="facts"><div><dt>Role</dt><dd>{host.role || "—"}</dd></div><div><dt>OS</dt><dd>{host.os || "—"}</dd></div><div><dt>Addresses</dt><dd>{host.addresses?.join(", ") || "—"}</dd></div><div><dt>Services</dt><dd>{host.services?.join(", ") || "—"}</dd></div></dl>{host.notes && <p class="row-reason">{host.notes}</p>}</article>)}</div></section>
          <section class="section-block"><div class="panel-heading"><h2>Runbooks</h2><span class="muted-note">{context.runbooks.length} entries</span></div>{context.runbooks.length === 0 ? <StateMessage title="No runbooks" detail="The current Trust-0 snapshot contains no runbooks." /> : <div class="runbook-list">{context.runbooks.map((runbook) => <details class="runbook" key={runbook.id}><summary><strong>{runbook.id}</strong><span>{runbook.targets?.length ? `targets: ${runbook.targets.join(", ")}` : "global"}</span></summary><pre class="context-text">{runbook.content}</pre></details>)}</div>}</section>
        </>
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
      <header class="page-header"><div><p class="eyebrow">Emergency authority</p><h1>Security</h1></div><Freshness error={error} value={lastFresh} /></header>
      {error && <p class="inline-error" role="alert">Emergency state refresh failed: {error}</p>}
      {!state ? <StateMessage title="Security state unavailable" detail={error || "Loading…"} bad={Boolean(error)} /> : (
        <div class="security-layout">
          <section class={`authority-card ${state.disabled ? "authority-card-disabled" : "authority-card-enabled"}`}><p class="eyebrow">Current state</p><h2>{state.disabled ? "AI access disabled" : "AI access enabled"}</h2><dl class="facts facts-large"><div><dt>Epoch</dt><dd>{state.epoch}</dd></div><div><dt>Last update</dt><dd>{formatTime(state.updated_at)}</dd></div><div><dt>Reason</dt><dd>{state.reason || "No reason recorded."}</dd></div></dl></section>
          <section class="panel security-explanation"><h2>Epoch semantics</h2><p>Re-enabling AI access does not revive capabilities from an older security epoch. Old-epoch grants remain stale permanently.</p>{state.disabled ? <button class="button button-primary" type="button" onClick={() => { setMutationError(""); setEnableOpen(true); }}>Enable AI access</button> : <p class="empty">AI access is already enabled. Global revoke remains available in the header.</p>}</section>
        </div>
      )}
      {enableOpen && <ConfirmDialog title="Enable AI access" description="This increases active authority for grants in the current epoch. Older-epoch capabilities remain stale." confirmLabel="Enable AI access" requireReason requiredPhrase="ENABLE AI ACCESS" busy={busy} error={mutationError} onCancel={() => !busy && setEnableOpen(false)} onConfirm={enable} />}
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
    : route === "grants" ? <GrantsPage />
    : route === "jobs" ? <JobsPage />
    : route === "audit" ? <AuditPageView />
    : route === "targets" ? <TargetsPage />
    : route === "context" ? <ContextPage />
    : <SecurityPage onAuthorityChanged={() => refreshOverview()} />;

  const revokeDisabled = Boolean(overview && !overviewError && overview.authority.disabled);

  return (
    <div class="app-shell">
      <header class="topbar">
        <a class="brand" href="#/overview" aria-label="Tethys Sentinel overview"><span class="brand-mark">T</span><span><strong>Tethys Sentinel</strong><small>operator</small></span></a>
        <div class="topbar-actions">
          {session ? <span class="operator-id" title={session.operator_identity}>mTLS operator · {session.operator_identity.slice(-12)}</span> : <span class="operator-id operator-id-bad">{sessionError ? "operator session error" : "establishing session…"}</span>}
          <button class="button button-danger emergency-button" type="button" disabled={revokeDisabled} onClick={() => { setRevokeError(""); setRevokeOpen(true); }}>{revokeDisabled ? "AI already disabled" : "REVOKE ALL"}</button>
        </div>
      </header>
      <AuthorityBanner overview={overview} error={overviewError} />
      {sessionError && <div class="session-error" role="alert">Operator session unavailable: {sessionError}. Mutations will fail closed.</div>}
      <div class="workspace"><nav class="sidebar" aria-label="Primary">{routes.map((item) => <a key={item.name} href={`#/${item.name}`} class={route === item.name ? "active" : ""}>{item.label}</a>)}</nav><main>{page}</main></div>
      {revokeOpen && <ConfirmDialog title="REVOKE ALL AI authority" description="Control will advance the security epoch, disable global AI authority, invalidate every older capability permanently, and terminate running execution authority." confirmLabel="REVOKE ALL" destructive requireReason busy={revokeBusy} error={revokeError} onCancel={() => !revokeBusy && setRevokeOpen(false)} onConfirm={revokeAll} />}
    </div>
  );
}

const root = document.getElementById("app");
if (!root) throw new Error("operator UI root element is missing");
render(<App />, root);
