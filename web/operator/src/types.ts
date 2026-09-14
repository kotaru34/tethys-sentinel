export interface EmergencyState {
  epoch: number;
  disabled: boolean;
  updated_at?: string;
  reason?: string;
}

export interface JobCounts {
  staged: number;
  pending: number;
  claimed: number;
  running: number;
  succeeded: number;
  failed: number;
  canceled: number;
  expired: number;
}

export interface JobResult {
  success: boolean;
  exit_code: number;
  output_sha256?: string;
  error_kind?: string;
}

export interface Job {
  id: string;
  request_id: string;
  grant_id: string;
  agent: string;
  target: string;
  argv: string[];
  command_sha256: string;
  approval_id?: string;
  risk_category?: string;
  scope_key?: string;
  created_at: string;
  expires_at: string;
  status: string;
  claimed_at?: string;
  started_at?: string;
  completed_at?: string;
  result?: JobResult;
}

export interface AuditEvent {
  sequence: number;
  id: string;
  timestamp: string;
  kind: string;
  actor?: string;
  grant_id?: string;
  target?: string;
  argv?: string[];
  decision?: string;
  category?: string;
  scope_key?: string;
  approval_id?: string;
  reason?: string;
  metadata?: Record<string, string>;
  prev_hash: string;
  hash: string;
}

export interface Overview {
  authority: EmergencyState;
  counts: {
    active_grants: number;
    pending_approvals: number;
    jobs: JobCounts;
  };
  recent_failures: Job[];
  recent_audit: AuditEvent[];
}

export interface Approval {
  id: string;
  grant_id: string;
  agent: string;
  target: string;
  argv: string[];
  category: string;
  risk_level: string;
  scope_key: string;
  risk_reason: string;
  agent_reason?: string;
  session_approval_allowed: boolean;
  status: "pending" | "decided" | "consumed";
  decision?: "deny" | "allow_once" | "allow_session";
  created_at: string;
  decided_at?: string;
  decision_actor?: string;
}

export interface ApprovalPage {
  items: Approval[];
  next_cursor?: string;
}

export interface SessionInfo {
  operator_identity: string;
  csrf_token: string;
}

export interface APIErrorShape {
  error?: string;
}
