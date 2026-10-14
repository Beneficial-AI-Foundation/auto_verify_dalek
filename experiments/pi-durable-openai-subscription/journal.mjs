/** Trusted-host admission only. No prompts, responses, credentials, or billing receipts. */
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, lstatSync, mkdirSync, realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { canonical, digest, reject, validateGrant } from './policy.mjs';

export class AdmissionJournal {
  #db; #grant; #closed = false;
  constructor(directory, value) {
    this.#grant = validateGrant(value);
    const root = resolve(directory);
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const info = lstatSync(root);
    if (!info.isDirectory() || info.isSymbolicLink() || realpathSync(root) !== root
        || (info.mode & 0o077) !== 0) reject('journal_directory_not_private');
    const file = join(root, 'admissions.sqlite');
    try { if (!lstatSync(file).isFile() || lstatSync(file).isSymbolicLink()) reject('unsafe_journal'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    this.#db = new DatabaseSync(file);
    chmodSync(file, 0o600);
    this.#db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=1000;');
    this.#db.exec('CREATE TABLE IF NOT EXISTS grant (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);'
      + 'CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, state TEXT NOT NULL, code TEXT, usage TEXT);'
      + 'CREATE TABLE IF NOT EXISTS stop (id INTEGER PRIMARY KEY CHECK(id=1), code TEXT NOT NULL);'
      + 'CREATE TABLE IF NOT EXISTS owner (id INTEGER PRIMARY KEY CHECK(id=1), role TEXT NOT NULL);');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const stored = this.#db.prepare('SELECT body FROM grant WHERE id=1').get();
      if (stored && stored.body !== canonical(this.#grant)) reject('original_grant_changed');
      this.#db.prepare('INSERT OR IGNORE INTO grant(id,body) VALUES(1,?)').run(canonical(this.#grant));
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#db.exec('ROLLBACK'); this.close(); throw error;
    }
  }
  get grant() { return structuredClone(this.#grant); }
  /** One role/Harness handle per journal, retained even after failed setup or clean close. */
  claim(role) {
    if (!Object.hasOwn(this.#grant.roleModels, role)) reject('role_or_grant_mismatch');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      if (this.#db.prepare('SELECT id FROM owner').get()
          || this.#db.prepare('SELECT id FROM attempts LIMIT 1').get() || this.blocked()) {
        reject('harness_already_claimed');
      }
      this.#db.prepare('INSERT INTO owner(id,role) VALUES(1,?)').run(role);
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }
  /** Unique request identity is deliberately conservative: even completed repeats are refused. */
  begin(identity, nowMs) {
    if (this.#closed) reject('journal_closed');
    const id = digest(identity);
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      if (nowMs < this.#grant.startedAtMs || nowMs >= this.#grant.deadlineMs) reject('deadline_exhausted');
      if (this.blocked()) reject('prior_request_quarantined');
      const rows = this.#db.prepare('SELECT id,state FROM attempts').all();
      if (rows.some(r => r.id === id)) reject('duplicate_request_quarantined');
      if (rows.some(r => r.state !== 'completed')) reject('prior_request_quarantined');
      if (rows.length >= this.#grant.maxInvocations) reject('invocation_limit');
      this.#db.prepare("INSERT INTO attempts(id,state) VALUES(?,'in_flight')").run(id);
      this.#db.exec('COMMIT');
      return id;
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }
  finish(id, code, usage = null) {
    if (this.#closed) reject('journal_closed');
    const result = this.#db.prepare("UPDATE attempts SET state=?,code=?,usage=? WHERE id=? AND state='in_flight'")
      .run(code === 'completed' ? 'completed' : 'quarantined', code, canonical(usage), id);
    if (result.changes !== 1) reject('journal_transition_refused');
  }
  blocked() { return this.#db.prepare('SELECT code FROM stop WHERE id=1').get()?.code ?? null; }
  quarantine(code) { this.#db.prepare('INSERT OR IGNORE INTO stop(id,code) VALUES(1,?)').run(code); }
  report() {
    return { grant: this.grant,
      claimedRole: this.#db.prepare('SELECT role FROM owner WHERE id=1').get()?.role ?? null,
      terminalCode: this.blocked(),
      attempts: this.#db.prepare('SELECT id,state,code,usage FROM attempts ORDER BY rowid').all()
        .map(r => ({ ...r, usage: r.usage === null ? null : JSON.parse(r.usage) })),
      costClassification: 'subscription_cost_unknown', costUsd: null, billingReceipt: null };
  }
  close() { if (!this.#closed) { this.#db.close(); this.#closed = true; } }
}
