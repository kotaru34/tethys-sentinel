import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import { getJSON, postJSON } from "./api";
import type { HistoryScope, Permissions, TargetPage } from "./operator-types";
import "./mcp-claim.css";

interface MCPClaimView {
  id: string;
  agent: string;
  purpose: string;
  targets: string[];
  permissions: Permissions;
  history: HistoryScope;
  grant_ttl_seconds: number;
  security_epoch: number;
  issued_at: string;
  expires_at: string;
}

interface MCPClaimResponse {
  claim: MCPClaimView;
  claim_code: string;
}

const permissions = (shell: boolean): Permissions => ({
  exec: true,
  shell,
  upload: false,
  download: false,
  history_read: false,
  notes_read: false,
  notes_write: false,
});

const history = (includeOutput: boolean): HistoryScope => ({
  current_session: false,
  previous_sessions: false,
  other_agents: false,
  include_output: includeOutput,
});

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : "unknown operator API error";
}

function MCPClaimLauncher() {
  const [open, setOpen] = useState(false);
  const [targets, setTargets] = useState<string[]>([]);
  const [selectedTargets, setSelectedTargets] = useState<string[]>([]);
  const [agent, setAgent] = useState("qwen-mcp");
  const [purpose, setPurpose] = useState("");
  const [claimTTL, setClaimTTL] = useState(120);
  const [grantTTL, setGrantTTL] = useState(3600);
  const [shell, setShell] = useState(false);
  const [includeOutput, setIncludeOutput] = useState(true);
  const [busy, setBusy] = useState(false);
  const [loadingTargets, setLoadingTargets] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<MCPClaimResponse | null>(null);
  const [copyState, setCopyState] = useState("");

  useEffect(() => {
    if (!open || targets.length > 0 || loadingTargets) return;
    const controller = new AbortController();
    setLoadingTargets(true);
    void getJSON<TargetPage>("/api/v1/targets", controller.signal)
      .then((page) => {
        setTargets(page.items.map((target) => target.name));
        setError("");
      })
      .catch((err) => {
        if (!(err instanceof DOMException && err.name === "AbortError")) setError(errorText(err));
      })
      .finally(() => setLoadingTargets(false));
    return () => controller.abort();
  }, [open, targets.length, loadingTargets]);

  const close = () => {
    setOpen(false);
    setResult(null);
    setCopyState("");
    setError("");
  };

  const toggleTarget = (target: string) => {
    setSelectedTargets((current) => current.includes(target)
      ? current.filter((item) => item !== target)
      : [...current, target]);
  };

  const issue = async (event: Event) => {
    event.preventDefault();
    setError("");
    setCopyState("");
    if (!agent.trim() || !purpose.trim() || selectedTargets.length === 0) {
      setError("Agent, purpose and at least one target are required.");
      return;
    }
    if (claimTTL < 30 || claimTTL > 300) {
      setError("Claim TTL must be between 30 and 300 seconds.");
      return;
    }
    if (grantTTL < 30 || grantTTL > 28800) {
      setError("Grant TTL must be between 30 and 28800 seconds.");
      return;
    }
    setBusy(true);
    try {
      const response = await postJSON<MCPClaimResponse>("/api/v1/mcp/claims", {
        agent: agent.trim(),
        purpose: purpose.trim(),
        targets: selectedTargets,
        permissions: permissions(shell),
        history: history(includeOutput),
        claim_ttl_seconds: claimTTL,
        grant_ttl_seconds: grantTTL,
      });
      setResult(response);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const copyClaim = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.claim_code);
      setCopyState("Copied. The claim remains usable only until its expiry or first redemption.");
    } catch {
      setCopyState("Clipboard write failed; select and copy the claim manually.");
    }
  };

  return (
    <>
      <button class="mcp-claim-launcher" type="button" onClick={() => setOpen(true)} aria-haspopup="dialog">
        Connect MCP
      </button>
      {open && (
        <div class="mcp-claim-backdrop" role="presentation">
          <section class="mcp-claim-dialog" role="dialog" aria-modal="true" aria-labelledby="mcp-claim-title">
            <div class="mcp-claim-heading">
              <div>
                <p class="mcp-claim-eyebrow">One-time bootstrap</p>
                <h2 id="mcp-claim-title">Connect Sentinel MCP</h2>
              </div>
              <button class="mcp-claim-close" type="button" onClick={close} aria-label="Close">×</button>
            </div>

            {result ? (
              <div class="mcp-claim-result">
                <p class="mcp-claim-warning">This claim is shown once. It expires at {new Date(result.claim.expires_at).toLocaleString()} and is invalid after first redemption.</p>
                <label class="mcp-claim-field">
                  <span>One-time claim</span>
                  <textarea readOnly rows={3} value={result.claim_code} onFocus={(event) => event.currentTarget.select()} />
                </label>
                <div class="mcp-claim-actions">
                  <button class="mcp-claim-primary" type="button" onClick={() => void copyClaim()}>Copy claim</button>
                  <button class="mcp-claim-secondary" type="button" onClick={close}>Done</button>
                </div>
                {copyState && <p class="mcp-claim-note" role="status">{copyState}</p>}
                <div class="mcp-claim-command">
                  <span>On the MCP host run</span>
                  <code>sentinelctl mcp claim</code>
                  <p>Paste the claim into the hidden prompt. Sentinel installs the resulting capability atomically; the running MCP server does not need a restart.</p>
                </div>
              </div>
            ) : (
              <form onSubmit={issue}>
                <div class="mcp-claim-grid">
                  <label class="mcp-claim-field"><span>Agent</span><input value={agent} onInput={(event) => setAgent(event.currentTarget.value)} autocomplete="off" /></label>
                  <label class="mcp-claim-field"><span>Purpose</span><input value={purpose} onInput={(event) => setPurpose(event.currentTarget.value)} autocomplete="off" placeholder="e.g. infrastructure administration" /></label>
                  <label class="mcp-claim-field"><span>Claim TTL, seconds</span><input type="number" min="30" max="300" value={claimTTL} onInput={(event) => setClaimTTL(Number(event.currentTarget.value))} /></label>
                  <label class="mcp-claim-field"><span>Grant TTL, seconds</span><input type="number" min="30" max="28800" value={grantTTL} onInput={(event) => setGrantTTL(Number(event.currentTarget.value))} /></label>
                </div>

                <fieldset class="mcp-claim-targets">
                  <legend>Targets</legend>
                  {loadingTargets ? <p>Loading targets…</p> : targets.length === 0 ? <p>No targets available.</p> : targets.map((target) => (
                    <label key={target}><input type="checkbox" checked={selectedTargets.includes(target)} onChange={() => toggleTarget(target)} /><span>{target}</span></label>
                  ))}
                </fieldset>

                <div class="mcp-claim-switches">
                  <label><input type="checkbox" checked={shell} onChange={(event) => setShell(event.currentTarget.checked)} /><span>Allow arbitrary Python code (shell authority)</span></label>
                  <label><input type="checkbox" checked={includeOutput} onChange={(event) => setIncludeOutput(event.currentTarget.checked)} /><span>Allow command output readback</span></label>
                </div>

                <p class="mcp-claim-note">Execution is always enabled. Upload, download, notes and broader history permissions stay disabled for this MCP bootstrap flow.</p>
                {error && <p class="mcp-claim-error" role="alert">{error}</p>}
                <div class="mcp-claim-actions">
                  <button class="mcp-claim-secondary" type="button" onClick={close} disabled={busy}>Cancel</button>
                  <button class="mcp-claim-primary" type="submit" disabled={busy || loadingTargets}>{busy ? "Issuing…" : "Issue one-time claim"}</button>
                </div>
              </form>
            )}
          </section>
        </div>
      )}
    </>
  );
}

const root = document.getElementById("mcp-claim-root");
if (root) render(<MCPClaimLauncher />, root);
