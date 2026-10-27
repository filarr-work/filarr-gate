// La chaîne peut-elle METTRE EN SERVICE cette étiquette sur le service hébergé ? — contrat gate-heberge-1 § 10.1, PH5, PH6.
//
// Node seul, aucune dépendance : .github/workflows/deploy-host.yml le lance AVANT `npm ci`, lu sur la branche par défaut.
//
//   node scripts/release/host-deploy.mjs decide --tag vX.Y.Z[-security] --tag-commit <sha> --sums SHA256SUMS \
//        --journal-ref <sha de release-journal> --activity <activité.jsonl> \
//        --kind release|security [--advisory GHSA-…] [--severity low|medium|high|critical] --ancestor true|false \
//        [--now <ISO>] [--github-output <fichier>]
//   node scripts/release/host-deploy.mjs last-deployed --journal journal.jsonl     → le commit en service, ou rien
//
// La règle :
//  - LE JOURNAL EST CELUI DE LA CHAÎNE (revue H1) : la branche release-journal est linéaire, chaque commit est du robot
//    de la chaîne (`github-actions[bot]`, comme auteur et comme auteur de la validation), le fichier ne fait que
//    grandir, et l'activité du dépôt chez GitHub (qui a poussé, et comment : `GET /repos/:dépôt/activity`) ne montre
//    que des poussées du robot, sans poussée forcée ni suppression, enchaînées jusqu'au sommet relu ; l'entrée
//    « published » de l'étiquette a été ajoutée par une de ces poussées ;
//  - l'étiquette a son entrée « published » au journal public (écrite par release.yml à la RÉCEPTION de l'étiquette),
//    une seule, dont le COMMIT est celui de l'étiquette signée (`--tag-commit`, lu par tag-check) et dont l'empreinte
//    du code (`sha256:` + SHA-256 du SHA256SUMS téléchargé de la publication) est la même ;
//  - publication ordinaire : SEPT JOURS au moins entre `publishedAt` de cette entrée (jamais la date que porte
//    l'étiquette) et maintenant ; sinon REFUS ;
//  - correctif de sécurité accepté (tag-check : kind=security, avis existant, clé de rôle security) : sans délai, si
//    une version est EN SERVICE et que le commit de l'étiquette en descend (`--ancestor true`, calculé par la chaîne
//    avec git merge-base), et que la gravité de l'avis est connue ; une condition manque → publication ordinaire.
//  - l'entrée à écrire au journal : `deployed` (publishedAt de l'entrée « published », deployedAt maintenant) ou
//    `security` (publishedAt = deployedAt = maintenant, la mention du délai levé, l'avis, la gravité).

import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { DELAY_SECONDS, SEVERITIES, codeHashOf } from './journal.mjs';

/** Le robot de la chaîne, seul auteur admis sur la branche du journal. */
export const JOURNAL_BOT = { name: 'github-actions[bot]', email: '41898282+github-actions[bot]@users.noreply.github.com' };
export const JOURNAL_REF = 'refs/heads/release-journal';
const ZERO = /^0{40}$/;
const SHA = /^[0-9a-f]{40}([0-9a-f]{24})?$/;

/** Les entrées du journal (une par ligne), les lignes illisibles ignorées. */
export function readJournal(text) {
  const out = [];
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    try {
      const e = JSON.parse(line);
      if (e && typeof e === 'object') out.push(e);
    } catch {
      /* une ligne illisible n'est pas une entrée */
    }
  }
  return out;
}

/** La dernière mise en service (`deployed` ou `security`), par `deployedAt`. */
export function lastDeployed(entries) {
  let best = null;
  for (const e of entries) {
    if ((e.kind !== 'deployed' && e.kind !== 'security') || typeof e.deployedAt !== 'string') continue;
    if (!best || Date.parse(e.deployedAt) > Date.parse(best.deployedAt)) best = e;
  }
  return best;
}

/** La gravité d'un avis GitHub, à l'échelle du journal (`moderate` de l'échelle globale = `medium`). */
export function journalSeverity(raw) {
  const s = String(raw ?? '').trim().toLowerCase();
  if (s === 'moderate') return 'medium';
  return SEVERITIES.includes(s) ? s : null;
}

const isBot = (p) => Boolean(p) && p.name === JOURNAL_BOT.name && p.email === JOURNAL_BOT.email;
const refusal = (refused, detail) => ({ ok: false, refused, detail });

/**
 * La PROVENANCE du journal (revue H1) : rend les entrées du sommet et le commit qui a ajouté l'entrée « published »
 * de l'étiquette (`null` si elle n'y est pas : `decide` refuse alors), ou un refus.
 *
 * @param {{ commits: Array<{ sha: string, parents: string[], author: { name: string, email: string },
 *           committer: { name: string, email: string }, journal: string }>,
 *           activity: Array<{ activity_type?: string, ref?: string, before?: string, after?: string, actor?: string | null }>,
 *           tip: string, tag: string }} input  `commits` du plus ancien au sommet (`git log --reverse`)
 */
export function checkJournalProvenance({ commits, activity, tip, tag }) {
  if (!Array.isArray(commits) || commits.length === 0 || commits.at(-1).sha !== tip) {
    return refusal('journal-tip', `le sommet relu (${tip}) n'est pas le dernier commit de release-journal`);
  }
  const index = new Map(commits.map((c, i) => [c.sha, i]));
  for (const [i, c] of commits.entries()) {
    const want = i === 0 ? [] : [commits[i - 1].sha];
    if (!Array.isArray(c.parents) || c.parents.join(' ') !== want.join(' ')) {
      return refusal('journal-history', `release-journal n'est pas linéaire au commit ${c.sha}`);
    }
    if (!isBot(c.author) || !isBot(c.committer)) {
      return refusal('journal-author', `le commit ${c.sha} de release-journal n'est pas du robot de la chaîne (${c.author?.name ?? '?'})`);
    }
    const before = i === 0 ? '' : commits[i - 1].journal;
    if (typeof c.journal !== 'string' || !c.journal.startsWith(before) || (c.journal !== '' && !c.journal.endsWith('\n'))) {
      return refusal('journal-rewritten', `le commit ${c.sha} réécrit journal.jsonl au lieu d'y ajouter des lignes`);
    }
  }

  // L'activité chez GitHub : des poussées du robot seulement, sans réécriture, enchaînées jusqu'au sommet
  const events = (Array.isArray(activity) ? activity : []).filter((e) => e && e.ref === JOURNAL_REF);
  for (const e of events) {
    if (e.activity_type === 'force_push' || e.activity_type === 'branch_deletion') {
      return refusal('journal-rewritten', `release-journal a été réécrite (${e.activity_type}, ${e.after ?? '?'})`);
    }
    if (e.activity_type !== 'push' && e.activity_type !== 'branch_creation') {
      return refusal('journal-activity', `activité inattendue sur release-journal : ${e.activity_type}`);
    }
    if (e.actor !== JOURNAL_BOT.name) return refusal('journal-actor', `release-journal a reçu une poussée de ${e.actor ?? '?'}`);
  }
  const used = new Set();
  let cur = tip;
  // L'indice du plus ancien commit NON couvert par l'activité relue (-1 : tout est couvert, depuis la création)
  let floor = -1;
  for (;;) {
    const e = events.find((x) => x.after === cur && !used.has(x));
    if (!e) {
      if (cur === tip) return refusal('journal-activity', `aucune poussée du robot n'a posé le sommet ${tip} de release-journal`);
      // L'activité que GitHub garde s'arrête ici : rien jusqu'à ce commit compris n'est couvert
      floor = index.get(cur);
      break;
    }
    used.add(e);
    const before = e.before ?? '';
    if (ZERO.test(before)) {
      if (e.activity_type !== 'branch_creation') return refusal('journal-activity', 'une poussée sans commit d’avant qui ne crée pas la branche');
      break;
    }
    if (!SHA.test(before) || !index.has(before) || index.get(before) >= index.get(cur)) {
      return refusal('journal-rewritten', `la poussée ${before}..${cur} n'est pas dans l'historique de release-journal`);
    }
    cur = before;
  }
  if (events.some((e) => !used.has(e))) return refusal('journal-rewritten', 'une poussée sur release-journal ne mène pas au sommet relu (historique remplacé)');

  // L'entrée « published » de l'étiquette : une seule, ajoutée par une poussée relue
  const final = commits.at(-1).journal;
  const lines = final.split('\n').filter((l) => {
    try {
      const e = JSON.parse(l);
      return Boolean(e) && e.kind === 'published' && e.tag === tag;
    } catch {
      return false;
    }
  });
  if (lines.length > 1) return refusal('published-twice', `deux entrées « published » pour ${tag} au journal public`);
  const entries = readJournal(final);
  if (lines.length === 0) return { ok: true, entries, introducedBy: null };
  const at = commits.findIndex((c) => c.journal.split('\n').includes(lines[0]));
  if (!(at > floor)) return refusal('journal-uncovered', `l'entrée « published » de ${tag} n'a pas été ajoutée par une poussée relue du robot`);
  return { ok: true, entries, introducedBy: commits[at].sha };
}

/** L'historique de release-journal lu par git (du plus ancien au sommet), avec journal.jsonl à chaque commit. */
export function gitJournalHistory(ref, cwd = process.cwd()) {
  const git = (args) => execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'pipe'] });
  const out = [];
  for (const line of git(['log', '--reverse', '--format=%H%x09%P%x09%an%x09%ae%x09%cn%x09%ce', ref]).split('\n')) {
    if (!line) continue;
    const [sha, parents, an, ae, cn, ce] = line.split('\t');
    let journal = '';
    try {
      journal = git(['show', `${sha}:journal.jsonl`]);
    } catch {
      journal = '';
    }
    out.push({ sha, parents: parents ? parents.split(' ') : [], author: { name: an, email: ae }, committer: { name: cn, email: ce }, journal });
  }
  return out;
}

/**
 * @param {{ entries: object[], tag: string, tagCommit: string, codeHash: string, kind: string, advisory?: string,
 *           severity?: string, ancestor: boolean, now: number }} input
 */
export function decide({ entries, tag, tagCommit, codeHash, kind, advisory, severity, ancestor, now }) {
  if (!SHA.test(tagCommit ?? '')) return refusal('tag-commit', 'le commit de l’étiquette vérifiée manque');
  const all = entries.filter((e) => e.kind === 'published' && e.tag === tag);
  if (all.length === 0) return refusal('not-published', `aucune entrée « published » pour ${tag} au journal public`);
  if (all.length > 1) return refusal('published-twice', `deux entrées « published » pour ${tag} au journal public`);
  const published = all[0];
  // H1 : la signature lie l'étiquette à SON commit ; l'entrée du journal doit nommer ce même commit
  if (published.commit !== tagCommit) {
    return refusal('commit', `le journal nomme le commit ${published.commit}, l'étiquette signée vise ${tagCommit}`);
  }
  if (published.codeHash !== codeHash) {
    return refusal('code-hash', `l'empreinte de la publication (${codeHash}) n'est pas celle du journal (${published.codeHash})`);
  }
  const nowIso = new Date(Math.floor(now / 1000) * 1000).toISOString();
  const base = { version: published.version, tag, commit: published.commit, codeHash };
  if (kind === 'security') {
    const sev = journalSeverity(severity);
    const last = lastDeployed(entries);
    let refused = null;
    if (!advisory) refused = 'advisory-missing';
    else if (!last) refused = 'nothing-deployed';
    else if (ancestor !== true) refused = 'not-from-deployed';
    else if (!sev) refused = 'severity-unknown';
    if (!refused) {
      return { ok: true, entry: { ...base, kind: 'security', publishedAt: nowIso, deployedAt: nowIso, advisory, severity: sev } };
    }
    const ordinary = decide({ entries, tag, tagCommit, codeHash, kind: 'release', now });
    return { ...ordinary, securityRefused: refused };
  }
  const waited = (now - Date.parse(published.publishedAt)) / 1000;
  if (!(waited >= DELAY_SECONDS)) {
    const left = Math.ceil((DELAY_SECONDS - waited) / 3600);
    return refusal('seven-days', `publiée le ${published.publishedAt} : encore ${left} h avant les sept jours`);
  }
  return { ok: true, entry: { ...base, kind: 'deployed', publishedAt: published.publishedAt, deployedAt: nowIso } };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [cmd] = process.argv.slice(2);
  const arg = (name) => {
    const i = process.argv.indexOf(`--${name}`);
    return i > 0 ? process.argv[i + 1] : undefined;
  };
  if (cmd === 'last-deployed') {
    if (!arg('journal')) {
      console.error('usage : host-deploy.mjs last-deployed --journal <journal.jsonl>');
      process.exit(2);
    }
    process.stdout.write(lastDeployed(readJournal(readFileSync(arg('journal'), 'utf8')))?.commit ?? '');
    process.exit(0);
  }
  if (cmd !== 'decide' || !arg('tag') || !arg('tag-commit') || !arg('sums') || !arg('kind') || !arg('journal-ref') || !arg('activity')) {
    console.error('usage : host-deploy.mjs decide --tag t --tag-commit sha --sums f --journal-ref sha --activity f --kind release|security --ancestor true|false');
    process.exit(2);
  }
  const provenance = checkJournalProvenance({
    commits: gitJournalHistory(arg('journal-ref')),
    activity: readJournal(readFileSync(arg('activity'), 'utf8')),
    tip: arg('journal-ref'),
    tag: arg('tag'),
  });
  const result = provenance.ok
    ? decide({
        entries: provenance.entries,
        tag: arg('tag'),
        tagCommit: arg('tag-commit'),
        codeHash: codeHashOf(readFileSync(arg('sums'))),
        kind: arg('kind'),
        advisory: arg('advisory') || undefined,
        severity: arg('severity') || undefined,
        ancestor: arg('ancestor') === 'true',
        now: arg('now') ? Date.parse(arg('now')) : Date.now(),
      })
    : provenance;
  console.log(JSON.stringify({ ...result, ...(provenance.ok ? { journalEntryBy: provenance.introducedBy } : {}) }, null, 2));
  const out = arg('github-output');
  if (out && result.ok) {
    const e = result.entry;
    const lines = [`entry_kind=${e.kind}`, `version=${e.version}`, `commit=${e.commit}`, `code_hash=${e.codeHash}`, `published_at=${e.publishedAt}`, `deployed_at=${e.deployedAt}`];
    if (e.kind === 'security') lines.push(`advisory=${e.advisory}`, `severity=${e.severity}`);
    if (result.securityRefused) lines.push(`security_refused=${result.securityRefused}`);
    appendFileSync(out, lines.join('\n') + '\n');
  }
  process.exit(result.ok ? 0 : 1);
}
