/**
 * LA MISE EN SERVICE DU SERVICE HÉBERGÉ (contrat gate-heberge-1 § 10.1, PH5 à PH7) :
 *  - `.github/workflows/deploy-host.yml`, lu comme un texte (rien n'est déclenché) ; les gardes communes à
 *    tous les workflows (actions figées par SHA, aucun `${{ }}` dans un script, aucun secret en clair) sont
 *    celles de `test/workflows.test.ts`, qui le parcourt aussi ;
 *  - `scripts/release/host-deploy.mjs`, la décision : sept jours depuis l'entrée « published » du journal
 *    public, ou correctif de sécurité accepté ; l'entrée nomme le commit de l'étiquette signée, et le journal est
 *    celui de la chaîne (revue H1).
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkJournalProvenance, decide, JOURNAL_BOT, JOURNAL_REF, journalSeverity, lastDeployed, readJournal, type JournalActivity, type JournalCommit } from '../scripts/release/host-deploy.mjs';
import { checkEntry, codeHashOf, SECURITY_NOTE } from '../scripts/release/journal.mjs';

const repo = join(__dirname, '..');
const read = (...p: string[]) => readFileSync(join(repo, ...p), 'utf8').replace(/\r\n/g, '\n');
const deployHost = read('.github', 'workflows', 'deploy-host.yml');
const release = read('.github', 'workflows', 'release.yml');

/** Les travaux d'un fichier de workflow et leurs `needs` (même lecture que workflows.test.ts). */
function jobs(text: string): Map<string, { body: string; needs: string[] }> {
  const part = text.slice(text.indexOf('\njobs:\n'));
  const map = new Map<string, { body: string; needs: string[] }>();
  const re = /^ {2}([A-Za-z][\w-]*):\n((?: {4}.*\n|\n)*)/gm;
  for (const m of part.matchAll(re)) {
    const body = m[2]!;
    const needs = /^ {4}needs: (.*)$/m.exec(body)?.[1] ?? '';
    map.set(m[1]!, { body, needs: needs.replace(/[[\]\s]/g, '').split(',').filter(Boolean) });
  }
  return map;
}

describe('deploy-host.yml', () => {
  const all = jobs(deployHost);

  it('lancée à la main seulement, avec une étiquette, depuis la branche par défaut', () => {
    const on = deployHost.slice(deployHost.indexOf('\non:\n'), deployHost.indexOf('\nenv:\n'));
    expect(on).toMatch(/^\non:\n {2}workflow_dispatch:\n {4}inputs:\n {6}tag:\n/);
    expect(on).not.toMatch(/push|pull_request|schedule|workflow_run|release:/);
    expect(deployHost).toMatch(/^permissions:\n {2}contents: read/m);
    expect(all.get('verify')!.body).toContain('[ "$GITHUB_REF" = "refs/heads/$DEFAULT_BRANCH" ]');
  });

  it('vérifier, essayer, mettre en service, journal : rien ne part sans la vérification et les essais', () => {
    expect([...all.keys()]).toEqual(['verify', 'test', 'deploy', 'journal']);
    expect(all.get('verify')!.needs).toEqual([]);
    expect(all.get('test')!.needs).toEqual(['verify']);
    expect(all.get('deploy')!.needs).toEqual(['verify', 'test']);
    expect(all.get('journal')!.needs).toEqual(['verify', 'deploy']);
  });

  it('signature relue deux fois contre release-signers de la branche par défaut ; journal lu sur release-journal', () => {
    const verify = all.get('verify')!.body;
    for (const f of ['.github/release-signers', 'scripts/release/tag-check.mjs', 'scripts/release/journal.mjs', 'scripts/release/host-deploy.mjs']) expect(verify).toContain(f);
    expect(verify).toContain('git show "FETCH_HEAD:$f"');
    expect(verify).toContain('git show "refs/remotes/origin/release-journal:journal.jsonl"');
    expect(verify).toContain('node "$RUNNER_TEMP/tag-check.mjs" --tag "$TAG"');
    expect(verify).toContain('gpg.ssh.allowedSignersFile="$RUNNER_TEMP/release-signers" verify-tag "$TAG"');
    expect(verify).toContain('étiquette légère');
    expect(verify).toContain('--sums "$RUNNER_TEMP/release/SHA256SUMS"');
    expect(verify).toContain('git merge-base --is-ancestor "$last" "$commit"');
    expect(verify).toContain('host/filarr-gate-host-$VERSION');
  });

  it('H1 : la décision lie l’entrée du journal au commit de l’étiquette SIGNÉE, et le journal à la chaîne', () => {
    const verify = all.get('verify')!.body;
    // Le commit que la chaîne transmet est celui que tag-check a lu dans l'objet signé, jamais celui du journal
    expect(verify).toMatch(/^ {6}commit: \$\{\{ steps\.check\.outputs\.commit \}\}$/m);
    expect(verify).not.toContain('commit: ${{ steps.decide.outputs.commit }}');
    expect(verify).toContain('node "$RUNNER_TEMP/host-deploy.mjs" decide --tag "$TAG" --tag-commit "$TAG_COMMIT"');
    expect(verify).toContain('TAG_COMMIT: ${{ steps.check.outputs.commit }}');
    // Le journal relu par git (sommet figé) et l'activité du dépôt chez GitHub (qui a poussé, et comment)
    expect(verify).toContain('--journal-ref "$(cat "$RUNNER_TEMP/journal-tip")" --activity "$RUNNER_TEMP/journal-activity.jsonl"');
    expect(verify).toContain('gh api --paginate "repos/$GITHUB_REPOSITORY/activity?ref=refs/heads/release-journal&per_page=100"');
    expect(verify).toContain('git rev-parse refs/remotes/origin/release-journal > "$RUNNER_TEMP/journal-tip"');
    // Deux fois : l'étiquette vise le commit signé, et l'entrée de journal retenue nomme ce même commit
    expect(verify).toContain('[ "$commit" != "$TAG_COMMIT" ]');
    expect(verify).toContain('CHECK_COMMIT: ${{ steps.check.outputs.commit }}');
    expect(verify).toContain('DECIDE_COMMIT: ${{ steps.decide.outputs.commit }}');
    expect(verify).toContain('[ "$CHECK_COMMIT" != "$DECIDE_COMMIT" ]');
    expect(verify).toMatch(/^ {6}module_sha256: \$\{\{ steps\.module\.outputs\.sha256 \}\}$/m);
  });

  it('le jeton de Cloudflare n’existe que dans l’environnement host-deploy, lu par le seul travail deploy', () => {
    const deploy = all.get('deploy')!.body;
    expect(deploy).toMatch(/^ {4}environment: host-deploy$/m);
    expect(deploy).toContain('CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}');
    for (const [name, job] of all) if (name !== 'deploy') expect(job.body, name).not.toContain('CLOUDFLARE');
    expect(deployHost.match(/secrets\.CLOUDFLARE_API_TOKEN/g)).toHaveLength(1);
    for (const workflow of ['ci.yml', 'release.yml']) expect(read('.github', 'workflows', workflow)).not.toContain('CLOUDFLARE');
  });

  it('M6 : à côté du jeton, aucun script d’installation, aucun cache, aucune construction', () => {
    const deploy = all.get('deploy')!.body;
    const installs = deploy.split('\n').filter((l) => /\bnpm (ci|install|i)\b/.test(l));
    expect(installs.length).toBeGreaterThan(0);
    for (const l of installs) expect(l, l).toMatch(/npm ci --ignore-scripts/);
    expect(deploy).not.toMatch(/cache: npm|npm run |npm exec|npx (?!wrangler deploy )/);
    expect(deploy).not.toMatch(/build\.mjs|wrangler secret|--dry-run/);
  });

  it('met en service le module REBÂTI depuis l’étiquette, son empreinte comparée à SHA256SUMS ; un seul wrangler', () => {
    const deploy = all.get('deploy')!.body;
    expect(deploy).toContain('npx wrangler deploy "$RUNNER_TEMP/module/filarr-gate-host-$VERSION.js" --no-bundle');
    expect(deploy).toContain('--config packages/host/wrangler.jsonc');
    for (const v of ['HOST_CODE_HASH:$CODE_HASH', 'HOST_BUILD_REF:$TAG', 'HOST_DEPLOYED_AT:$DEPLOYED_AT', 'HOST_SECURITY_ADVISORY:$ADVISORY']) expect(deploy).toContain(v);
    // Le module vient du travail SANS jeton qui l'a rebâti, par artefact ; son empreinte est revérifiée ici
    expect(deploy).toContain('name: host-module');
    expect(deploy).not.toContain('name: host-release');
    expect(deploy).toContain('MODULE_SHA256: ${{ needs.verify.outputs.module_sha256 }}');
    expect(deploy).toContain('[ "$got" != "$MODULE_SHA256" ]');
    expect(deploy.indexOf('[ "$got" != "$MODULE_SHA256" ]')).toBeLessThan(deploy.indexOf('npx wrangler deploy'));
    expect(deploy).toContain('$CONTROL_URL/.well-known/filarr-gate-host.json');
    expect(deployHost.match(/npx wrangler /g)).toHaveLength(1);
  });

  it('les essais et la mise en service extraient l’ÉTIQUETTE, jamais un commit lu au journal', () => {
    for (const name of ['test', 'deploy']) {
      const body = all.get(name)!.body;
      expect(body, name).toContain('ref: refs/tags/${{ needs.verify.outputs.tag }}');
      expect(body, name).not.toMatch(/ref: \$\{\{ needs\.verify\.outputs\.commit \}\}/);
      // L'arbre extrait est encore celui que la vérification a lu (une étiquette déplacée entre-temps est refusée)
      expect(body, name).toContain('[ "$(git rev-parse HEAD)" != "$COMMIT" ]');
    }
    expect(deployHost).not.toMatch(/ref: \$\{\{ needs\.verify\.outputs\.commit \}\}/);
  });

  it('le module se rebâtit depuis l’étiquette, son SHA-256 est celui de SHA256SUMS, il part par artefact', () => {
    const test = all.get('test')!.body;
    for (const step of ['npm ci', 'npm run typecheck', 'npx vitest run --maxWorkers=2', 'npm run docs:check']) expect(test).toContain(step);
    expect(test).toContain('node scripts/host/build.mjs --outfile "$RUNNER_TEMP/module/filarr-gate-host-$VERSION.js"');
    expect(test).toContain('MODULE_SHA256: ${{ needs.verify.outputs.module_sha256 }}');
    expect(test).toContain('[ "$got" != "$MODULE_SHA256" ]');
    expect(test).toContain('cmp "$RUNNER_TEMP/module/filarr-gate-host-$VERSION.js" "$RUNNER_TEMP/release/filarr-gate-host-$VERSION.js"');
    expect(test).toContain('name: host-module');
    expect(test).not.toContain('secrets.');
    expect(test).not.toMatch(/^ {4}environment:/m);
  });

  it('écrit l’entrée « deployed » ou « security » du journal public', () => {
    const journal = all.get('journal')!.body;
    expect(journal).toContain('--published-at "$PUBLISHED_AT" --deployed-at "$DEPLOYED_AT"');
    expect(journal).toContain('--advisory "$ADVISORY" --severity "$SEVERITY"');
    expect(journal).toContain('node "$RUNNER_TEMP/journal.mjs" append journal.jsonl "$@"');
    expect(journal).toContain('git push origin release-journal');
  });

  it('release.yml joint le module du service à la publication, compté dans SHA256SUMS (PH7)', () => {
    expect(jobs(release).get('pack')!.body).toContain('release/a/host/*.js');
    expect(jobs(release).get('github-release')!.body).toContain('cp "release/a/host/filarr-gate-host-$VERSION.js"');
    expect(read('scripts', 'pack-check.mjs')).toContain('host/filarr-gate-host-${version}.js');
  });
});

describe('host-deploy.mjs : sept jours, ou correctif de sécurité', () => {
  const sums = `${'a'.repeat(64)}  library/filarr-gate-0.3.0.tgz\n`;
  const codeHash = codeHashOf(sums);
  const commit = '1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c';
  const published = { kind: 'published', version: '0.3.0', tag: 'v0.3.0', commit, codeHash, publishedAt: '2026-10-20T10:00:00.000Z' };
  const security = { ...published, tag: 'v0.3.1-security', version: '0.3.1', publishedAt: '2026-10-21T10:00:00.000Z' };
  const deployedBefore = { kind: 'deployed', version: '0.2.0', tag: 'v0.2.0', commit: 'b'.repeat(40), codeHash: `sha256:${'c'.repeat(64)}`, publishedAt: '2026-10-01T00:00:00.000Z', deployedAt: '2026-10-09T00:00:00.000Z' };
  const at = (iso: string) => Date.parse(iso);
  const tagCommit = commit;

  it('lit le journal et sa dernière mise en service ; gravité à l’échelle du journal', () => {
    const entries = readJournal([JSON.stringify(published), 'pas du json', JSON.stringify(deployedBefore), ''].join('\n'));
    expect(entries).toHaveLength(2);
    expect(lastDeployed(entries)?.tag).toBe('v0.2.0');
    expect(journalSeverity('moderate')).toBe('medium');
    expect(journalSeverity('HIGH')).toBe('high');
    expect(journalSeverity('grave')).toBeNull();
  });

  it('refuse avant sept jours COMPTÉS depuis l’entrée « published » (jamais la date de l’étiquette)', () => {
    expect(decide({ entries: [published], tag: 'v0.3.0', tagCommit, codeHash, kind: 'release', ancestor: false, now: at('2026-10-27T09:59:59.000Z') })).toMatchObject({ ok: false, refused: 'seven-days' });
    const ok = decide({ entries: [published], tag: 'v0.3.0', tagCommit, codeHash, kind: 'release', ancestor: false, now: at('2026-10-27T10:00:00.000Z') });
    expect(ok).toMatchObject({ ok: true, entry: { kind: 'deployed', commit, publishedAt: published.publishedAt, deployedAt: '2026-10-27T10:00:00.000Z' } });
    if (ok.ok) expect(checkEntry(ok.entry)).toEqual([]);
  });

  it('refuse une étiquette absente du journal, ou dont l’empreinte n’est pas celle de la publication', () => {
    const later = at('2027-01-01T00:00:00.000Z');
    expect(decide({ entries: [], tag: 'v0.3.0', tagCommit, codeHash, kind: 'release', ancestor: false, now: later })).toMatchObject({ ok: false, refused: 'not-published' });
    expect(decide({ entries: [published], tag: 'v0.3.0', tagCommit, codeHash: `sha256:${'0'.repeat(64)}`, kind: 'release', ancestor: false, now: later })).toMatchObject({ ok: false, refused: 'code-hash' });
  });

  it('H1 : refuse une entrée « published » dont le commit n’est pas celui de l’étiquette signée, ou en double', () => {
    const later = at('2027-01-01T00:00:00.000Z');
    // Le scénario de la revue : une entrée antidatée pour une étiquette signée EXISTANTE, avec le commit piégé X
    const trapped = { ...published, commit: '9'.repeat(40), publishedAt: '2026-01-01T00:00:00.000Z' };
    expect(decide({ entries: [trapped], tag: 'v0.3.0', tagCommit, codeHash, kind: 'release', ancestor: false, now: later })).toMatchObject({ ok: false, refused: 'commit' });
    expect(decide({ entries: [published, trapped], tag: 'v0.3.0', tagCommit, codeHash, kind: 'release', ancestor: false, now: later })).toMatchObject({ ok: false, refused: 'published-twice' });
    expect(decide({ entries: [published], tag: 'v0.3.0', tagCommit: '', codeHash, kind: 'release', ancestor: false, now: later })).toMatchObject({ ok: false, refused: 'tag-commit' });
    // Le correctif de sécurité ramené à l'ordinaire suit la même règle
    expect(decide({ entries: [deployedBefore, { ...security, commit: '9'.repeat(40) }], tag: 'v0.3.1-security', tagCommit, codeHash, kind: 'security', advisory: 'GHSA-2f9x-4c7m-q8vr', severity: 'high', ancestor: true, now: later })).toMatchObject({ ok: false, refused: 'commit' });
  });

  it('correctif de sécurité accepté : sans délai, publication = mise en service, avis et gravité au journal', () => {
    const r = decide({ entries: [deployedBefore, security], tag: 'v0.3.1-security', tagCommit, codeHash, kind: 'security', advisory: 'GHSA-2f9x-4c7m-q8vr', severity: 'moderate', ancestor: true, now: at('2026-10-21T10:05:00.000Z') });
    expect(r).toMatchObject({ ok: true, entry: { kind: 'security', publishedAt: '2026-10-21T10:05:00.000Z', deployedAt: '2026-10-21T10:05:00.000Z', advisory: 'GHSA-2f9x-4c7m-q8vr', severity: 'medium' } });
    if (r.ok) expect(checkEntry({ ...r.entry, note: SECURITY_NOTE })).toEqual([]);
  });

  it('une condition du correctif manque : publication ordinaire, sept jours', () => {
    const now = at('2026-10-21T10:05:00.000Z');
    const base = { entries: [deployedBefore, security], tag: 'v0.3.1-security', tagCommit, codeHash, kind: 'security', advisory: 'GHSA-2f9x-4c7m-q8vr', severity: 'high', ancestor: true, now };
    expect(decide({ ...base, ancestor: false })).toMatchObject({ ok: false, refused: 'seven-days', securityRefused: 'not-from-deployed' });
    expect(decide({ ...base, entries: [security] })).toMatchObject({ ok: false, securityRefused: 'nothing-deployed' });
    expect(decide({ ...base, severity: '' })).toMatchObject({ ok: false, securityRefused: 'severity-unknown' });
    expect(decide({ ...base, advisory: undefined })).toMatchObject({ ok: false, securityRefused: 'advisory-missing' });
    const later = decide({ ...base, ancestor: false, now: at('2026-10-28T10:00:00.000Z') });
    expect(later).toMatchObject({ ok: true, entry: { kind: 'deployed', tag: 'v0.3.1-security' }, securityRefused: 'not-from-deployed' });
    if (later.ok) expect(checkEntry(later.entry)).toEqual([]);
  });
});

describe('host-deploy.mjs : le journal vient de la chaîne (revue H1)', () => {
  const bot = { ...JOURNAL_BOT };
  const sha = (n: number) => n.toString(16).padStart(40, '0').replace(/^0/, 'f');
  const zero = '0'.repeat(40);
  const line = (o: Record<string, unknown>) => JSON.stringify(o) + '\n';
  const pub = line({ kind: 'published', tag: 'v0.3.1', version: '0.3.1', commit: 'a'.repeat(40), codeHash: `sha256:${'b'.repeat(64)}`, publishedAt: '2026-10-16T00:37:16.000Z' });
  const first = line({ kind: 'published', tag: 'v0.2.0', version: '0.2.0', commit: 'c'.repeat(40), codeHash: `sha256:${'d'.repeat(64)}`, publishedAt: '2026-10-10T15:47:12.000Z' });
  const dep = line({ kind: 'deployed', tag: 'v0.3.1', version: '0.3.1', commit: 'a'.repeat(40), codeHash: `sha256:${'b'.repeat(64)}`, publishedAt: '2026-10-16T00:37:16.000Z', deployedAt: '2026-10-26T23:48:33.000Z' });
  // L'historique réel de la branche, à sa forme : création (v0.2.0), publication de v0.3.1, mise en service
  const commits = (): JournalCommit[] => [
    { sha: sha(1), parents: [], author: bot, committer: bot, journal: first },
    { sha: sha(2), parents: [sha(1)], author: bot, committer: bot, journal: first + pub },
    { sha: sha(3), parents: [sha(2)], author: bot, committer: bot, journal: first + pub + dep },
  ];
  const activity = (): JournalActivity[] => [
    { activity_type: 'push', ref: JOURNAL_REF, before: sha(2), after: sha(3), actor: bot.name },
    { activity_type: 'push', ref: JOURNAL_REF, before: sha(1), after: sha(2), actor: bot.name },
    { activity_type: 'branch_creation', ref: JOURNAL_REF, before: zero, after: sha(1), actor: bot.name },
    { activity_type: 'push', ref: 'refs/heads/main', before: sha(8), after: sha(9), actor: 'matbel91765' },
  ];
  const check = (over: Partial<{ commits: JournalCommit[]; activity: JournalActivity[]; tip: string; tag: string }> = {}) =>
    checkJournalProvenance({ commits: commits(), activity: activity(), tip: sha(3), tag: 'v0.3.1', ...over });

  it('un journal linéaire, du robot, poussé par lui sans réécriture : accepté, avec le commit qui a ajouté l’entrée', () => {
    const r = check();
    expect(r).toMatchObject({ ok: true, introducedBy: sha(2) });
    if (r.ok) expect(r.entries.map((e) => e.kind)).toEqual(['published', 'published', 'deployed']);
    // Une étiquette absente : la provenance passe, `decide` refuse ensuite (not-published)
    expect(check({ tag: 'v9.9.9' })).toMatchObject({ ok: true, introducedBy: null });
  });

  it('refuse un commit qui n’est pas du robot de la chaîne (auteur ou auteur de la validation)', () => {
    const c = commits();
    c[1] = { ...c[1]!, author: { name: 'matbel91765', email: 'matbel91765@users.noreply.github.com' } };
    expect(check({ commits: c })).toMatchObject({ ok: false, refused: 'journal-author' });
    const d = commits();
    d[2] = { ...d[2]!, committer: { name: 'github-actions[bot]', email: 'faux@example.test' } };
    expect(check({ commits: d })).toMatchObject({ ok: false, refused: 'journal-author' });
  });

  it('refuse une branche réécrite : poussée forcée, suppression, poussée hors de l’historique, fichier réécrit', () => {
    expect(check({ activity: [...activity(), { activity_type: 'force_push', ref: JOURNAL_REF, before: sha(7), after: sha(3), actor: bot.name }] })).toMatchObject({ ok: false, refused: 'journal-rewritten' });
    expect(check({ activity: [...activity(), { activity_type: 'branch_deletion', ref: JOURNAL_REF, before: sha(7), after: zero, actor: bot.name }] })).toMatchObject({ ok: false, refused: 'journal-rewritten' });
    // Une poussée d'un historique remplacé depuis (elle ne mène pas au sommet relu)
    expect(check({ activity: [...activity(), { activity_type: 'push', ref: JOURNAL_REF, before: sha(1), after: sha(7), actor: bot.name }] })).toMatchObject({ ok: false, refused: 'journal-rewritten' });
    const c = commits();
    c[2] = { ...c[2]!, journal: pub + dep };
    expect(check({ commits: c })).toMatchObject({ ok: false, refused: 'journal-rewritten' });
  });

  it('refuse une poussée d’un autre que le robot, un sommet qu’aucune poussée relue n’a posé, une fusion', () => {
    const a = activity();
    a[0] = { ...a[0]!, actor: 'matbel91765' };
    expect(check({ activity: a })).toMatchObject({ ok: false, refused: 'journal-actor' });
    expect(check({ activity: activity().slice(1) })).toMatchObject({ ok: false, refused: 'journal-activity' });
    expect(check({ tip: sha(2) })).toMatchObject({ ok: false, refused: 'journal-tip' });
    const c = commits();
    c[2] = { ...c[2]!, parents: [sha(2), sha(1)] };
    expect(check({ commits: c })).toMatchObject({ ok: false, refused: 'journal-history' });
  });

  it('une activité gardée seulement en partie : l’entrée doit avoir été ajoutée par une poussée relue', () => {
    // GitHub ne rend plus la création : les poussées relues couvrent sha(2) et sha(3)
    expect(check({ activity: activity().slice(0, 2) })).toMatchObject({ ok: true, introducedBy: sha(2) });
    // Plus que la dernière poussée : l'entrée de v0.3.1, ajoutée avant, n'est plus couverte
    expect(check({ activity: activity().slice(0, 1) })).toMatchObject({ ok: false, refused: 'journal-uncovered' });
  });

  it('refuse deux entrées « published » pour la même étiquette', () => {
    const c = commits();
    const twice = first + pub + dep + pub.replace('"a', '"9');
    c.push({ sha: sha(4), parents: [sha(3)], author: bot, committer: bot, journal: twice });
    const a = [{ activity_type: 'push', ref: JOURNAL_REF, before: sha(3), after: sha(4), actor: bot.name }, ...activity()];
    expect(check({ commits: c, activity: a, tip: sha(4) })).toMatchObject({ ok: false, refused: 'published-twice' });
  });
});
