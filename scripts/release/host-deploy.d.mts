// Types de scripts/release/host-deploy.mjs (Node seul, importé par les essais).
export type JournalRecord = Record<string, string>;
export type DeployDecision =
  | { ok: true; entry: JournalRecord; securityRefused?: string }
  | {
      ok: false;
      refused: 'tag-commit' | 'not-published' | 'published-twice' | 'commit' | 'code-hash' | 'seven-days';
      detail: string;
      securityRefused?: string;
    };
export interface JournalCommit {
  sha: string;
  parents: string[];
  author: { name: string; email: string };
  committer: { name: string; email: string };
  journal: string;
}
export interface JournalActivity {
  activity_type?: string;
  ref?: string;
  before?: string;
  after?: string;
  actor?: string | null;
}
export type JournalProvenance =
  | { ok: true; entries: JournalRecord[]; introducedBy: string | null }
  | {
      ok: false;
      refused: 'journal-tip' | 'journal-history' | 'journal-author' | 'journal-rewritten' | 'journal-activity' | 'journal-actor' | 'published-twice' | 'journal-uncovered';
      detail: string;
    };
export const JOURNAL_BOT: { name: string; email: string };
export const JOURNAL_REF: string;
export function readJournal(text: string): JournalRecord[];
export function lastDeployed(entries: JournalRecord[]): JournalRecord | null;
export function journalSeverity(raw: unknown): string | null;
export function checkJournalProvenance(input: { commits: JournalCommit[]; activity: JournalActivity[]; tip: string; tag: string }): JournalProvenance;
export function gitJournalHistory(ref: string, cwd?: string): JournalCommit[];
export function decide(input: {
  entries: JournalRecord[];
  tag: string;
  tagCommit: string;
  codeHash: string;
  kind: string;
  advisory?: string;
  severity?: string;
  ancestor: boolean;
  now: number;
}): DeployDecision;
