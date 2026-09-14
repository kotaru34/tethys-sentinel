import type { AuditEvent, Job } from "./types";

export interface Permissions {
  exec: boolean;
  shell: boolean;
  upload: boolean;
  download: boolean;
  history_read: boolean;
  notes_read: boolean;
  notes_write: boolean;
}

export interface HistoryScope {
  current_session: boolean;
  previous_sessions: boolean;
  other_agents: boolean;
  include_output: boolean;
}

export type GrantState = "active" | "disabled" | "stale_epoch" | "revoked" | "expired";

export interface Grant {
  id: string;
  purpose: string;
  agent: string;
  targets: string[];
  permissions: Permissions;
  history: HistoryScope;
  security_epoch: number;
  issued_at: string;
  expires_at: string;
  revoked_at?: string;
}

export interface GrantView extends Grant {
  state: GrantState;
}

export interface GrantPage {
  items: GrantView[];
  next_cursor?: string;
}

export interface IssueGrantResponse {
  grant: Grant;
  token: string;
}

export interface JobPage {
  items: Job[];
  next_cursor?: string;
}

export interface AuditPage {
  items: AuditEvent[];
  next_cursor?: string;
}

export interface TargetView {
  name: string;
  address: string;
  user: string;
  host_key_algorithm: string;
  host_key_fingerprint: string;
  host_key: string;
}

export interface TargetPage {
  items: TargetView[];
}

export interface ContextHost {
  name: string;
  role?: string;
  os?: string;
  services?: string[];
  addresses?: string[];
  notes?: string;
}

export interface ContextRunbook {
  id: string;
  targets?: string[];
  content: string;
}

export interface ContextView {
  version: string;
  trust_level: string;
  policy: string;
  instructions: string;
  hosts: ContextHost[];
  runbooks: ContextRunbook[];
}
