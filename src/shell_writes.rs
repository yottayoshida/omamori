use std::path::{Component, Path, PathBuf};

use crate::engine::hook::{FileProtectionVerdict, fold_name};

const MAX_DEPTH: u8 = 5;
const MAX_BRACE_WORDS: usize = 64;
const MAX_BRACE_GROUPS: usize = 16;
// ponytail: past this many directories read for globs in one command, a glob
// is matched against the listed protected paths alone.
const MAX_GLOB_DIRS: usize = 32;
const MAX_GLOB_ENTRIES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Word {
    pub(crate) text: String,
    pub(crate) glob: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Lexed {
    Word(Word),
    Separator { and: bool, or: bool, pipe: bool },
    Open,
    Close,
    Unsafe,
    Redirect(String),
    Nested(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    Tree,
    // Not judged as a directory above a protected file: `mkdir -p ~/.config`
    // and `touch` change nothing under it.
    Name,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Cd {
        target: Word,
        sure: bool,
    },
    Mention {
        word: Word,
        exempt: bool,
    },
    Reads {
        exempt: bool,
    },
    // Something in the command can carry a name reader's output on to a
    // reader, or make a reader's name run something else.
    Unsafe,
    Write {
        target: Word,
        reach: Reach,
        sources: Vec<Word>,
        into: bool,
    },
    // A subshell, substitution or `bash -c` begins or ends: a `cd` inside
    // does not move where the commands after it run.
    Enter,
    Leave,
    // An `||`: what follows runs when what came before failed, a `cd`
    // included.
    Or,
}

pub(crate) struct Surroundings<'a> {
    pub(crate) home: Option<&'a Path>,
    pub(crate) bases: Vec<PathBuf>,
    pub(crate) tree_bases: Vec<PathBuf>,
    pub(crate) protected: &'a [PathBuf],
    pub(crate) secret_files: &'a [PathBuf],
    pub(crate) secret_dirs: &'a [PathBuf],
}

type Judge<'a> = &'a dyn Fn(&str, Option<&Path>) -> Option<FileProtectionVerdict>;
type Saved = (Vec<PathBuf>, Vec<PathBuf>, Option<Vec<PathBuf>>);

pub(crate) fn shell_write_verdict(
    command: &str,
    surroundings: &Surroundings<'_>,
    judge: Judge<'_>,
    judge_secret: &dyn Fn(&str) -> Option<FileProtectionVerdict>,
) -> Option<(String, FileProtectionVerdict)> {
    let home = surroundings.home.map(|h| h.to_string_lossy().into_owned());
    let mut events = Vec::new();
    collect_events(command, home.as_deref(), 0, &mut events);
    let mut names = surroundings.bases.clone();
    let mut trees = surroundings.tree_bases.clone();
    let mut before_sure: Option<Vec<PathBuf>> = None;
    let mut scopes: Vec<Saved> = Vec::new();
    let mut dirs_read = 0;
    let mut canonical = std::collections::HashMap::new();
    // Not exempt anywhere when the output of a name reader can go on to
    // something that reads it (a pipe anywhere, a process substitution), or
    // when the command defines what a reader's name runs.
    let exemptions_hold = !events.iter().any(|e| matches!(e, Event::Unsafe));
    let secret_ids: Vec<(u64, u64)> = surroundings
        .secret_files
        .iter()
        .chain(surroundings.secret_dirs)
        .filter_map(|p| identity(p))
        .collect();
    let mut secret_dirs_read = 0;
    for event in events {
        match event {
            Event::Unsafe => {}
            Event::Enter => scopes.push((names.clone(), trees.clone(), before_sure.clone())),
            Event::Leave => {
                if let Some((n, t, b)) = scopes.pop() {
                    (names, trees, before_sure) = (n, t, b);
                }
            }
            Event::Or => {
                if let Some(before) = before_sure.take() {
                    for r in before {
                        push_new(&mut trees, r);
                    }
                }
            }
            Event::Cd { target, sure } => {
                let Some(next_trees) = resolve_cd(&target, &trees) else {
                    if target.glob {
                        for anchor in anchors(&target.text, &names.clone()) {
                            let pattern = lexical(&PathBuf::from(absolute_text(
                                &target.text,
                                anchor.as_deref(),
                            )));
                            let depth = folded_components(&pattern).len();
                            for dir in surroundings.secret_dirs {
                                let level: PathBuf = dir.components().take(depth).collect();
                                if folded_components(dir).len() >= depth
                                    && glob_reaches(&pattern, &level)
                                {
                                    push_new(&mut names, level.clone());
                                    push_new(&mut trees, level);
                                }
                            }
                        }
                    }
                    continue;
                };
                for r in resolve_cd(&target, &names).unwrap_or_default() {
                    push_new(&mut names, r);
                }
                // Not kept beside the old base after `cd x &&`: the command
                // runs only in `x`, and the old base would let a directory
                // above a protected file pass as harmless there.
                if sure {
                    before_sure = Some(std::mem::replace(&mut trees, next_trees));
                } else {
                    for r in next_trees {
                        push_new(&mut trees, r);
                    }
                }
            }
            Event::Mention { word, exempt } => {
                if exempt && exemptions_hold {
                    continue;
                }
                if let Some(hit) = judge_mention(
                    &word,
                    &names,
                    surroundings,
                    &secret_ids,
                    judge_secret,
                    &mut canonical,
                    &mut secret_dirs_read,
                ) {
                    return Some(hit);
                }
            }
            Event::Reads { exempt } => {
                if exempt && exemptions_hold {
                    continue;
                }
                // Where the command runs now, not every place a `cd` ever
                // named: `cd <dir> && ls; cd ~/proj && make` reads in proj.
                for base in &trees {
                    let in_secret_dir = surroundings.secret_dirs.iter().any(|d| same_path(base, d))
                        || identity(base).is_some_and(|id| secret_ids.contains(&id));
                    if in_secret_dir && let Some(v) = judge_secret(&base.to_string_lossy()) {
                        return Some((base.to_string_lossy().into_owned(), v));
                    }
                }
            }
            Event::Write {
                target,
                reach,
                sources,
                into,
            } => {
                let place = Place {
                    names: &names,
                    trees: &trees,
                    protected: surroundings.protected,
                };
                if let Some(hit) = judge_target(
                    &target,
                    reach,
                    &sources,
                    into,
                    &place,
                    judge,
                    &mut dirs_read,
                ) {
                    return Some(hit);
                }
            }
        }
    }
    None
}

fn same_path(a: &Path, b: &Path) -> bool {
    folded_components(a) == folded_components(b)
}

// Not judged by which program reads: readers are unbounded and a renamed one
// would pass, while naming the secret at all is rare.
fn judge_mention(
    word: &Word,
    names: &[PathBuf],
    surroundings: &Surroundings<'_>,
    secret_ids: &[(u64, u64)],
    judge_secret: &dyn Fn(&str) -> Option<FileProtectionVerdict>,
    canonical: &mut std::collections::HashMap<PathBuf, Option<PathBuf>>,
    dirs_read: &mut usize,
) -> Option<(String, FileProtectionVerdict)> {
    let mut texts = vec![word.text.as_str()];
    if let Some((_, value)) = word.text.split_once('=') {
        texts.push(value);
    }
    // Not only a separate word: a short option takes its value attached
    // (`curl -d@FILE`, `-T FILE` written `-TFILE`).
    if word.text.starts_with('-')
        && !word.text.starts_with("--")
        && let Some(value) = word.text.get(2..).filter(|v| !v.is_empty())
    {
        texts.push(value);
    }
    // Not only the word as a path: `curl --data-binary @FILE`, `-F f=@FILE`
    // and `-pass file:FILE` read FILE.
    for at in 0..texts.len() {
        for prefix in ["@", "file://", "file:"] {
            if let Some(rest) = texts[at].strip_prefix(prefix) {
                texts.push(rest);
            }
        }
    }
    for text in texts {
        if text.is_empty() {
            continue;
        }
        for anchor in anchors(text, names) {
            let path = lexical(&PathBuf::from(absolute_text(text, anchor.as_deref())));
            if word.glob {
                for secret in surroundings.secret_files {
                    let reaches_far_enough = surroundings
                        .secret_dirs
                        .iter()
                        .any(|d| folded_components(&path).len() >= folded_components(d).len());
                    if reaches_far_enough
                        && glob_reaches(&path, secret)
                        && let Some(v) = judge_secret(&secret.to_string_lossy())
                    {
                        return Some((text.to_string(), v));
                    }
                }
                if let Some(hit) = secret_in_glob_directory(&path, judge_secret, dirs_read) {
                    return Some((text.to_string(), hit));
                }
                if let Some(hit) = secret_name_below_glob(&path, judge_secret, dirs_read) {
                    return Some((text.to_string(), hit));
                }
                continue;
            }
            // Not resolved from the lexical form alone: `link/../x` is where
            // `link` points, then up.
            let raw = PathBuf::from(absolute_text(text, anchor.as_deref()));
            let mut resolved = Vec::new();
            for spelling in [&path, &raw] {
                if let Some(r) = canonical
                    .entry(spelling.clone())
                    .or_insert_with(|| std::fs::canonicalize(spelling).ok())
                    .clone()
                {
                    resolved.push(r);
                }
            }
            for candidate in std::iter::once(&path).chain(resolved.iter()) {
                // Not by spelling alone: a macOS firmlink spelling of the same
                // directory (`/System/Volumes/Data/...`) is no link.
                let names_secret = surroundings
                    .secret_files
                    .iter()
                    .chain(surroundings.secret_dirs)
                    .any(|s| same_path(candidate, s))
                    || identity(candidate).is_some_and(|id| secret_ids.contains(&id));
                // Not only the configured key: a copy or a key elsewhere is
                // as good to a forger, and a name alone that exists nowhere
                // (`grep -rn audit-secret src/`) is no read.
                let secret_named_file = candidate
                    .file_name()
                    .is_some_and(|f| fold_name(&f.to_string_lossy()).starts_with("audit-secret"))
                    && candidate.symlink_metadata().is_ok();
                if (names_secret || secret_named_file)
                    && let Some(v) = judge_secret(&candidate.to_string_lossy())
                {
                    return Some((text.to_string(), v));
                }
            }
        }
    }
    None
}

// ponytail: past this many places a command may run, a further `cd` is not
// followed; each one would double the paths a later write is judged under.
const MAX_BASES: usize = 16;

// Not only the configured key: a retired key, an epoch or pending file, or a
// copy elsewhere is found by its name when a glob's directory is read.
fn secret_in_glob_directory(
    pattern: &Path,
    judge_secret: &dyn Fn(&str) -> Option<FileProtectionVerdict>,
    dirs_read: &mut usize,
) -> Option<FileProtectionVerdict> {
    glob_matches_in_directory(pattern, dirs_read)
        .into_iter()
        .filter(|found| {
            found
                .file_name()
                .is_some_and(|n| fold_name(&n.to_string_lossy()).starts_with("audit-secret"))
        })
        .find_map(|found| judge_secret(&found.to_string_lossy()))
}

// A secret-named file below a directory pattern: `/backup/*/audit-secret`,
// `~/.local/share/omam*/audit-secret.1.retired`.
fn secret_name_below_glob(
    pattern: &Path,
    judge_secret: &dyn Fn(&str) -> Option<FileProtectionVerdict>,
    dirs_read: &mut usize,
) -> Option<FileProtectionVerdict> {
    let last = pattern.file_name()?.to_string_lossy();
    if has_glob(&last) || !fold_name(&last).starts_with("audit-secret") {
        return None;
    }
    glob_matches_in_directory(pattern.parent()?, dirs_read)
        .into_iter()
        .map(|dir| dir.join(last.as_ref()))
        .filter(|candidate| candidate.symlink_metadata().is_ok())
        .find_map(|candidate| judge_secret(&candidate.to_string_lossy()))
}

// Not a directory listed when it is itself a pattern, nor past the budget:
// each read is a filesystem call the hook waits on.
fn glob_matches_in_directory(pattern: &Path, dirs_read: &mut usize) -> Vec<PathBuf> {
    let (Some(parent), Some(last)) = (pattern.parent(), pattern.file_name()) else {
        return Vec::new();
    };
    let last = last.to_string_lossy();
    if has_glob(&parent.to_string_lossy()) || *dirs_read >= MAX_GLOB_DIRS {
        return Vec::new();
    }
    *dirs_read += 1;
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    entries
        .flatten()
        .take(MAX_GLOB_ENTRIES)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name_matches(last.as_bytes(), name.as_bytes()))
        .map(|name| parent.join(name))
        .collect()
}

#[cfg(unix)]
fn identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

#[cfg(not(unix))]
fn identity(_path: &Path) -> Option<(u64, u64)> {
    None
}

fn push_new(list: &mut Vec<PathBuf>, path: PathBuf) {
    if list.len() < MAX_BASES && !list.contains(&path) {
        list.push(path);
    }
}

fn resolve_cd(word: &Word, bases: &[PathBuf]) -> Option<Vec<PathBuf>> {
    if word.glob || word.text.contains('$') || word.text.contains('`') {
        return None;
    }
    let path = Path::new(&word.text);
    Some(if path.is_absolute() {
        vec![lexical(path)]
    } else {
        bases
            .iter()
            .take(MAX_BASES)
            .map(|b| lexical(&b.join(path)))
            .collect()
    })
}

struct Place<'a> {
    names: &'a [PathBuf],
    trees: &'a [PathBuf],
    protected: &'a [PathBuf],
}

fn anchors(text: &str, bases: &[PathBuf]) -> Vec<Option<PathBuf>> {
    if Path::new(text).is_relative() {
        bases.iter().map(|b| Some(b.clone())).collect()
    } else {
        vec![None]
    }
}

fn judge_target(
    target: &Word,
    reach: Reach,
    sources: &[Word],
    into: bool,
    place: &Place<'_>,
    judge: Judge<'_>,
    dirs_read: &mut usize,
) -> Option<(String, FileProtectionVerdict)> {
    if target.text.is_empty() {
        return None;
    }
    if Path::new(&target.text).is_relative() && place.names.is_empty() {
        return judge(&target.text, None).map(|v| (target.text.clone(), v));
    }
    let name_anchors = anchors(&target.text, place.names);

    if target.glob {
        return judge_glob(&target.text, &name_anchors, place, judge, dirs_read);
    }

    let mut names = vec![target.text.clone()];
    for source in sources {
        if let Some(name) = Path::new(&source.text).file_name() {
            names.push(format!("{}/{}", target.text, name.to_string_lossy()));
        }
    }
    for name in &names {
        for anchor in &name_anchors {
            if let Some(v) = judge(name, anchor.as_deref()) {
                return Some((name.clone(), v));
            }
        }
    }
    if reach != Reach::Tree {
        return None;
    }

    // The destination itself is replaced only when its contents are poured
    // in; `mv x ~/` writes `~/x`, not `~`.
    let roots: Vec<&String> = if sources.is_empty() || into {
        vec![&target.text]
    } else {
        names[1..].iter().collect()
    };
    for root in roots {
        for anchor in anchors(root, place.names) {
            let path = lexical(&PathBuf::from(absolute_text(root, anchor.as_deref())));
            if let Some(hit) = tail_below(&path, judge) {
                return Some((root.clone(), hit));
            }
        }
        // Not when any base leaves it above nothing protected: a relative
        // `find . -delete` run from HOME would otherwise be refused in every
        // project.
        let mut covering = None;
        for anchor in anchors(root, place.trees) {
            let path = lexical(&PathBuf::from(absolute_text(root, anchor.as_deref())));
            match place.protected.iter().find(|p| is_at_or_above(&path, p)) {
                Some(p) => covering = covering.or(Some(p)),
                None => {
                    covering = None;
                    break;
                }
            }
        }
        if let Some(protected) = covering
            && let Some(v) = judge(&protected.to_string_lossy(), None)
        {
            return Some((root.clone(), v));
        }
    }
    None
}

// A directory whose last components begin a protected name: `rm -rf
// proj/.claude` removes `proj/.claude/settings.json`. Not when nothing is
// there: every directory named `omamori` would otherwise be refused.
fn tail_below(path: &Path, judge: Judge<'_>) -> Option<FileProtectionVerdict> {
    let parts = folded_components(path);
    // Not a list of its own: the protected patterns are the one source, so a
    // name added there is followed here too.
    let tails = crate::engine::hook::PROTECTED_FILE_PATTERNS
        .iter()
        .filter(|(_, kind, _)| *kind == crate::engine::hook::MatchKind::Subpath);
    for (tail, _, _) in tails {
        let tail_parts: Vec<&str> = tail.split('/').collect();
        for k in 1..tail_parts.len() {
            let head = &tail_parts[..k];
            if parts.len() >= k
                && parts[parts.len() - k..]
                    .iter()
                    .map(String::as_str)
                    .eq(head.iter().copied())
            {
                let below = path.join(tail_parts[k..].join("/"));
                if below.symlink_metadata().is_err() {
                    continue;
                }
                if let Some(v) = judge(&below.to_string_lossy(), None) {
                    return Some(v);
                }
            }
        }
    }
    None
}

fn judge_glob(
    text: &str,
    name_anchors: &[Option<PathBuf>],
    place: &Place<'_>,
    judge: Judge<'_>,
    dirs_read: &mut usize,
) -> Option<(String, FileProtectionVerdict)> {
    for anchor in name_anchors {
        let pattern = lexical(&PathBuf::from(absolute_text(text, anchor.as_deref())));
        for protected in place.protected {
            if glob_reaches(&pattern, protected)
                && let Some(v) = judge(&protected.to_string_lossy(), None)
            {
                return Some((text.to_string(), v));
            }
        }
        for found in glob_matches_in_directory(&pattern, dirs_read) {
            if let Some(v) = judge(&found.to_string_lossy(), None) {
                return Some((text.to_string(), v));
            }
            if let Some(v) = tail_below(&found, judge) {
                return Some((text.to_string(), v));
            }
        }
    }
    None
}

fn has_glob(text: &str) -> bool {
    text.contains(['*', '?', '['])
}

fn absolute_text(text: &str, anchor: Option<&Path>) -> String {
    match anchor {
        Some(base) if Path::new(text).is_relative() => {
            base.join(text).to_string_lossy().into_owned()
        }
        _ => text.to_string(),
    }
}

fn lexical(path: &Path) -> PathBuf {
    let mut out: Vec<Component> = Vec::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.last(), Some(Component::Normal(_))) {
                    out.pop();
                }
            }
            other => out.push(other),
        }
    }
    out.iter().collect()
}

fn folded_components(path: &Path) -> Vec<String> {
    path.components()
        .map(|c| fold_name(&c.as_os_str().to_string_lossy()))
        .collect()
}

fn is_at_or_above(path: &Path, protected: &Path) -> bool {
    let (a, b) = (folded_components(path), folded_components(protected));
    a.len() <= b.len() && a[..] == b[..a.len()]
}

// Not only a pattern that matches a listed path: `rm ~/.omamori/*` names the
// base directory's contents, which are not listed.
fn glob_reaches(pattern: &Path, protected: &Path) -> bool {
    let (pat, target) = (folded_components(pattern), folded_components(protected));
    let shared = pat.len().min(target.len());
    pat[..shared]
        .iter()
        .zip(&target[..shared])
        .all(|(p, t)| name_matches(p.as_bytes(), t.as_bytes()))
}

// Not a match for a leading dot from a leading wildcard: the shell's `*`
// skips dotfiles, and `rm ~/*` does not reach `~/.omamori`.
fn name_matches(pattern: &[u8], name: &[u8]) -> bool {
    if name.first() == Some(&b'.') && pattern.first() != Some(&b'.') {
        return false;
    }
    component_matches(pattern, name)
}

// One remembered `*` is enough for a single component; a pattern that makes
// the matcher backtrack further would let a crafted command stall the hook.
fn component_matches(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() {
            match pattern[p] {
                b'*' => {
                    star = Some((p, n));
                    p += 1;
                    continue;
                }
                b'?' => {
                    p += 1;
                    n += 1;
                    continue;
                }
                b'[' => {
                    if let Some((matched, end)) = class_matches(&pattern[p..], name[n]) {
                        if matched {
                            p += end;
                            n += 1;
                            continue;
                        }
                    } else if name[n] == b'[' {
                        p += 1;
                        n += 1;
                        continue;
                    }
                }
                c if c == name[n] => {
                    p += 1;
                    n += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((sp, sn)) => {
                p = sp + 1;
                n = sn + 1;
                star = Some((sp, sn + 1));
            }
            None => return false,
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

fn class_matches(class: &[u8], c: u8) -> Option<(bool, usize)> {
    let mut i = 1;
    let negate = matches!(class.get(i), Some(b'!' | b'^'));
    if negate {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    while i < class.len() {
        if class[i] == b']' && !first {
            return Some((matched != negate, i + 1));
        }
        first = false;
        if class.get(i + 1) == Some(&b'-') && class.get(i + 2).is_some_and(|&e| e != b']') {
            if class[i] <= c && c <= class[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if class[i] == c {
                matched = true;
            }
            i += 1;
        }
    }
    None
}

fn collect_events(text: &str, home: Option<&str>, depth: u8, events: &mut Vec<Event>) {
    if depth > MAX_DEPTH {
        return;
    }
    let prepared = crate::unwrap::prepare_for_splitting(text);
    let mut segment: Vec<Word> = Vec::new();
    let mut lexed = lex(&prepared, home).into_iter().peekable();
    let mut after_or: Option<Option<usize>> = None;
    let nested = |inner: &str, events: &mut Vec<Event>| {
        events.push(Event::Enter);
        collect_events(inner, home, depth + 1, events);
        events.push(Event::Leave);
    };
    while let Some(item) = lexed.next() {
        match item {
            Lexed::Word(word) => segment.push(word),
            Lexed::Unsafe => events.push(Event::Unsafe),
            Lexed::Separator { and, or, pipe } => {
                if pipe {
                    events.push(Event::Unsafe);
                }
                flush(&segment, and, pipe, &mut after_or, home, depth, events);
                segment.clear();
                if or {
                    let cd =
                        matches!(events.last(), Some(Event::Cd { .. })).then(|| events.len() - 1);
                    after_or = Some(cd);
                }
            }
            Lexed::Open => events.push(Event::Enter),
            Lexed::Close => events.push(Event::Leave),
            Lexed::Nested(inner) => nested(&inner, events),
            Lexed::Redirect(op) => {
                // Not dropped when the target holds a substitution: its
                // command comes first, then the word it is part of.
                while let Some(Lexed::Nested(_)) = lexed.peek() {
                    if let Some(Lexed::Nested(inner)) = lexed.next() {
                        nested(&inner, events);
                    }
                }
                if !matches!(lexed.peek(), Some(Lexed::Word(_))) {
                    continue;
                }
                let Some(Lexed::Word(target)) = lexed.next() else {
                    continue;
                };
                if (redirect_writes_to(&op, &target) && target.text != "/dev/null")
                    || target.text.starts_with("<(")
                    || target.text.starts_with(">(")
                {
                    events.push(Event::Unsafe);
                }
                if redirect_writes_to(&op, &target) {
                    events.push(Event::Write {
                        target,
                        reach: Reach::Name,
                        sources: vec![],
                        into: false,
                    });
                } else if op.starts_with('<') && !op.starts_with("<<") {
                    events.push(Event::Mention {
                        word: target,
                        exempt: false,
                    });
                }
            }
        }
    }
    flush(&segment, false, false, &mut after_or, home, depth, events);
}

// `cd x || exit` is as sure as `cd x &&`: what follows runs only in `x`.
fn flush(
    segment: &[Word],
    then_and: bool,
    then_pipe: bool,
    after_or: &mut Option<Option<usize>>,
    home: Option<&str>,
    depth: u8,
    events: &mut Vec<Event>,
) {
    if let Some(cd) = after_or.take() {
        let exits = segment
            .first()
            .is_some_and(|w| matches!(w.text.as_str(), "exit" | "return"));
        match (exits, cd) {
            (true, Some(at)) => {
                if let Some(Event::Cd { sure, .. }) = events.get_mut(at) {
                    *sure = true;
                }
            }
            _ => events.push(Event::Or),
        }
    }
    segment_events(segment, then_and, then_pipe, home, depth, events);
}

fn redirect_writes_to(op: &str, target: &Word) -> bool {
    if !op.contains('>') {
        return false;
    }
    let dup = op.ends_with('&') && !op.starts_with('&');
    !(dup && (target.text == "-" || target.text.bytes().all(|b| b.is_ascii_digit())))
}

fn segment_events(
    words: &[Word],
    then_and: bool,
    then_pipe: bool,
    home: Option<&str>,
    depth: u8,
    events: &mut Vec<Event>,
) {
    let texts: Vec<String> = words.iter().map(|w| w.text.clone()).collect();
    mention_events(words, then_pipe, depth, events);
    let stripped = crate::unwrap::unwrap_transparent(&texts);
    let offset = if texts.ends_with(&stripped) {
        texts.len() - stripped.len()
    } else {
        0
    };
    let words = &words[offset..];
    let Some(first) = words.first() else {
        return;
    };
    if let Some(inner) = crate::unwrap::extract_shell_inner(&texts[offset..]) {
        events.push(Event::Enter);
        collect_events(&inner, home, depth + 1, events);
        events.push(Event::Leave);
        return;
    }
    let program = first.text.rsplit('/').next().unwrap_or(&first.text);
    program_events(program, &words[1..], then_and, home, depth, events);
}

const NAME_READERS: &[&str] = &[
    "ls", "stat", "test", "[", "[[", "cd", "pushd", "popd", "realpath", "readlink", "basename",
    "dirname", "du", "tree", "eza", "exa", "lsd", "fd", "find",
];

// Not exempt when its output goes on through a pipe (`ls -d <key> | xargs
// cat`), nor `find` or `fd` when they run or write something.
fn mention_events(words: &[Word], then_pipe: bool, depth: u8, events: &mut Vec<Event>) {
    let texts: Vec<String> = words.iter().map(|w| w.text.clone()).collect();
    let stripped = crate::unwrap::unwrap_transparent(&texts);
    let Some(program) = stripped.first() else {
        return;
    };
    let acts = match program.as_str() {
        "find" => stripped.iter().any(|t| {
            matches!(
                t.as_str(),
                "-exec"
                    | "-execdir"
                    | "-ok"
                    | "-okdir"
                    | "-delete"
                    | "-fprint"
                    | "-fprint0"
                    | "-fls"
                    | "-fprintf"
            )
        }),
        "fd" => stripped.iter().any(|t| {
            t.starts_with("--exec")
                || (t.starts_with('-') && !t.starts_with("--") && t.contains(['x', 'X']))
        }),
        _ => false,
    } || stripped
        .iter()
        .any(|t| t.contains("fromfile") || t.contains("files0-from"));
    if words.iter().any(|w| {
        matches!(
            w.text.as_str(),
            "function" | "alias" | "hash" | "coproc" | "mkfifo" | "enable"
        ) || w.text.ends_with("()")
            || w.text.starts_with("PATH=")
            || w.text.starts_with("<(")
            || w.text.starts_with(">(")
    }) {
        events.push(Event::Unsafe);
    }
    // Not by a path or inside a substitution: `/tmp/ls` may be `cat` renamed,
    // and what a substitution prints is read by the command around it.
    let exempt = NAME_READERS.contains(&program.as_str()) && !then_pipe && !acts && depth == 0;
    events.push(Event::Reads { exempt });
    events.extend(words.iter().map(|w| Event::Mention {
        word: w.clone(),
        exempt,
    }));
}

fn operands(args: &[Word]) -> Vec<Word> {
    let mut out = Vec::new();
    let mut options = true;
    for a in args {
        if options && a.text == "--" {
            options = false;
            continue;
        }
        if options && a.text.starts_with('-') && a.text.len() > 1 {
            continue;
        }
        // Not the `/dev/fd` name a process substitution becomes: what it
        // writes is read as its own command.
        if a.text.starts_with("<(") || a.text.starts_with(">(") {
            continue;
        }
        out.push(a.clone());
    }
    out
}

// Not `operands` for `chmod`: a mode may begin with `-` (`chmod -x f`), and
// read as an option it would leave the file to be taken for the mode.
fn mode_operands(program: &str, args: &[Word]) -> Vec<Word> {
    let mut out = Vec::new();
    let mut seen_mode = args.iter().any(|a| a.text.starts_with("--reference"));
    let mut options = true;
    for a in args {
        let t = a.text.as_str();
        let looks_like_mode = program == "chmod"
            && t.len() > 1
            && t.starts_with(['-', '+', '='])
            && t[1..]
                .bytes()
                .all(|c| b"rwxXstugoa+-=,01234567".contains(&c));
        if options && t == "--" {
            options = false;
        } else if !seen_mode && looks_like_mode {
            seen_mode = true;
        } else if options && t.starts_with('-') && t.len() > 1 {
        } else if !seen_mode {
            seen_mode = true;
        } else {
            out.push(a.clone());
        }
    }
    out
}

fn write(target: &Word, reach: Reach) -> Event {
    Event::Write {
        target: target.clone(),
        reach,
        sources: vec![],
        into: false,
    }
}

fn word(text: &str, glob: bool) -> Word {
    Word {
        text: text.to_string(),
        glob,
    }
}

fn program_events(
    program: &str,
    args: &[Word],
    then_and: bool,
    home: Option<&str>,
    depth: u8,
    events: &mut Vec<Event>,
) {
    match program {
        "cd" | "pushd" => {
            let target = operands(args)
                .into_iter()
                .next()
                .unwrap_or_else(|| word(home.unwrap_or("~"), false));
            if target.text != "-" {
                events.push(Event::Cd {
                    target,
                    sure: then_and,
                });
            }
        }
        "tee" | "sponge" => events.extend(operands(args).iter().map(|w| write(w, Reach::Tree))),
        "touch" | "mkdir" | "mkfifo" | "mknod" => {
            let ops = operands(args);
            let ops = if program == "mknod" {
                &ops[..ops.len().min(1)]
            } else {
                &ops[..]
            };
            events.extend(ops.iter().map(|w| write(w, Reach::Name)));
        }
        "truncate" | "rm" | "unlink" | "rmdir" | "shred" | "xattr" => {
            events.extend(operands(args).iter().map(|w| write(w, Reach::Tree)));
        }
        "chmod" | "chown" | "chgrp" | "chflags" => {
            events.extend(
                mode_operands(program, args)
                    .iter()
                    .map(|w| write(w, Reach::Tree)),
            );
        }
        "mv" | "ln" => {
            let ops = operands(args);
            let symbolic = program == "ln"
                && args.iter().any(|a| {
                    a.text == "--symbolic"
                        || (a.text.starts_with('-')
                            && !a.text.starts_with("--")
                            && a.text.contains('s'))
                });
            if let Some((dest, sources)) = ops.split_last() {
                // A hard link is a second name for the protected file, written
                // through later; a symbolic one does not change its target.
                let reach = if program == "mv" {
                    Some(Reach::Tree)
                } else if symbolic {
                    None
                } else {
                    Some(Reach::Name)
                };
                if let Some(reach) = reach {
                    events.extend(sources.iter().map(|w| write(w, reach)));
                }
                events.push(Event::Write {
                    target: dest.clone(),
                    reach: Reach::Tree,
                    sources: sources.to_vec(),
                    into: false,
                });
            }
        }
        "cp" | "install" | "rsync" | "ditto" | "gcp" => copy_events(program, args, events),
        "sed" | "gsed" => sed_events(args, events),
        "perl" => perl_events(args, events),
        "yq" => {
            if args.iter().any(|a| {
                a.text == "-i" || a.text == "--inplace" || a.text.starts_with("--inplace=")
            }) {
                events.extend(operands(args).iter().skip(1).map(|w| write(w, Reach::Tree)));
            }
        }
        "dd" => {
            for a in args {
                if let Some(rest) = a.text.strip_prefix("of=") {
                    events.push(write(&word(rest, a.glob), Reach::Tree));
                }
            }
        }
        "curl" => option_value_events(
            args,
            b"oDc",
            &[
                "output",
                "dump-header",
                "cookie-jar",
                "trace",
                "trace-ascii",
                "stderr",
            ],
            events,
        ),
        "wget" => option_value_events(
            args,
            b"Ooa",
            &["output-document", "output-file", "append-output"],
            events,
        ),
        "find" => find_events(args, home, depth, events),
        "xargs" => xargs_events(args, home, depth, events),
        _ => {}
    }
}

// Not only `-o FILE`: getopt bundles (`curl -fsSLo FILE`, `wget -qO FILE`)
// and attaches (`-oFILE`).
fn option_value_events(args: &[Word], shorts: &[u8], longs: &[&str], events: &mut Vec<Event>) {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        let t = a.text.as_str();
        if t == "--" {
            break;
        }
        if let Some(long) = t.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            if longs.contains(&name) {
                match value {
                    Some(v) => events.push(write(&word(v, a.glob), Reach::Tree)),
                    None => {
                        if let Some(v) = iter.next() {
                            events.push(write(v, Reach::Tree));
                        }
                    }
                }
            }
            continue;
        }
        let Some(letters) = t.strip_prefix('-') else {
            continue;
        };
        if let Some(at) = letters.bytes().position(|b| shorts.contains(&b)) {
            let rest = &letters[at + 1..];
            if rest.is_empty() {
                if let Some(v) = iter.next() {
                    events.push(write(v, Reach::Tree));
                }
            } else {
                events.push(write(&word(rest, a.glob), Reach::Tree));
            }
        }
    }
}

fn copy_events(program: &str, args: &[Word], events: &mut Vec<Event>) {
    let mut target: Option<Word> = None;
    let mut plain: Vec<Word> = Vec::new();
    let mut link = false;
    let mut iter = args.iter();
    let mut options = true;
    while let Some(a) = iter.next() {
        let t = a.text.as_str();
        if options && t == "--" {
            options = false;
        } else if options && (t == "-t" || t == "--target-directory") {
            target = iter.next().cloned();
        } else if options && let Some(rest) = t.strip_prefix("--target-directory=") {
            target = Some(word(rest, a.glob));
        } else if options && t.starts_with("-t") && !t.starts_with("--") {
            target = Some(word(&t[2..], a.glob));
        } else if options && t.starts_with('-') && t.len() > 1 {
            if t == "--link" || (!t.starts_with("--") && program == "cp" && t.contains('l')) {
                link = true;
            }
        } else {
            plain.push(a.clone());
        }
    }
    let (dest, sources) = match target {
        Some(t) => (t, plain),
        None => match plain.split_last() {
            Some((d, s)) => (d.clone(), s.to_vec()),
            None => return,
        },
    };
    if link {
        events.extend(sources.iter().map(|w| write(w, Reach::Name)));
    }
    let into = program == "ditto"
        || sources
            .iter()
            .any(|s| s.text.ends_with('/') || s.text.ends_with("/."));
    events.push(Event::Write {
        target: dest,
        reach: Reach::Tree,
        sources,
        into,
    });
}

fn sed_events(args: &[Word], events: &mut Vec<Event>) {
    let mut in_place = false;
    let mut scripted = false;
    let mut rest: Vec<Word> = Vec::new();
    let mut iter = args.iter().peekable();
    let mut options = true;
    while let Some(a) = iter.next() {
        let t = a.text.as_str();
        if options && t == "--" {
            options = false;
        } else if options && (t == "-e" || t == "-f" || t == "--expression" || t == "--file") {
            scripted = true;
            iter.next();
        } else if options && (t.starts_with("--expression=") || t.starts_with("--file=")) {
            scripted = true;
        } else if options && (t == "--in-place" || t.starts_with("--in-place=")) {
            in_place = true;
        } else if options && t.starts_with('-') && !t.starts_with("--") && t.len() > 1 {
            let letters = &t[1..];
            if let Some(at) = letters.find(['i', 'I']) {
                in_place = true;
                // Not the script: BSD sed reads the word after a bare `-i` or
                // `-I` as the backup suffix (`-i ''`, `-I .bak`).
                if at + 1 == letters.len()
                    && iter
                        .peek()
                        .is_some_and(|n| n.text.is_empty() || n.text.starts_with('.'))
                {
                    iter.next();
                }
            } else if letters.contains('e') || letters.contains('f') {
                scripted = true;
                iter.next();
            }
        } else if options && t.starts_with("--") {
        } else {
            rest.push(a.clone());
        }
    }
    if in_place {
        let files = if scripted {
            &rest[..]
        } else {
            rest.get(1..).unwrap_or(&[])
        };
        events.extend(files.iter().map(|w| write(w, Reach::Tree)));
    }
}

fn perl_events(args: &[Word], events: &mut Vec<Event>) {
    let mut in_place = false;
    let mut scripted = false;
    let mut rest: Vec<Word> = Vec::new();
    let mut iter = args.iter();
    let mut options = true;
    while let Some(a) = iter.next() {
        let t = a.text.as_str();
        if !options || !t.starts_with('-') || t.len() < 2 {
            rest.push(a.clone());
            options = false;
            continue;
        }
        if t == "--" {
            options = false;
            continue;
        }
        let letters = &t.as_bytes()[1..];
        for (at, &letter) in letters.iter().enumerate() {
            let tail_empty = at + 1 == letters.len();
            match letter {
                b'i' => {
                    in_place = true;
                    break;
                }
                b'e' | b'E' => {
                    scripted = true;
                    if tail_empty {
                        iter.next();
                    }
                    break;
                }
                b'M' | b'm' | b'I' | b'x' | b'C' | b'd' | b'D' => {
                    if tail_empty && matches!(letter, b'M' | b'm' | b'I') {
                        iter.next();
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    if in_place {
        let files = if scripted {
            &rest[..]
        } else {
            rest.get(1..).unwrap_or(&[])
        };
        events.extend(files.iter().map(|w| write(w, Reach::Tree)));
    }
}

const FIND_WRITERS: &[&str] = &[
    "rm", "unlink", "rmdir", "shred", "truncate", "chmod", "chown", "chgrp", "chflags", "xattr",
    "mv", "ln", "cp", "install", "rsync", "ditto", "touch", "tee", "sed", "gsed", "perl", "dd",
];

fn find_events(args: &[Word], home: Option<&str>, depth: u8, events: &mut Vec<Event>) {
    let mut i = 0;
    let mut starts: Vec<&Word> = Vec::new();
    while i < args.len() {
        match args[i].text.as_str() {
            "-H" | "-L" | "-P" | "-E" | "-X" | "-d" | "-s" | "-x" => i += 1,
            "-D" => i += 2,
            "-f" => {
                if let Some(start) = args.get(i + 1) {
                    starts.push(start);
                }
                i += 2;
            }
            t if t.starts_with("-O") => i += 1,
            _ => break,
        }
    }
    starts.extend(
        args[i.min(args.len())..]
            .iter()
            .take_while(|a| !(a.text.starts_with('-') || a.text == "(" || a.text == "!")),
    );
    let mut deletes = false;
    for (j, a) in args.iter().enumerate() {
        match a.text.as_str() {
            "-delete" => deletes = true,
            "-fprint" | "-fprint0" | "-fls" | "-fprintf" => {
                if let Some(file) = args.get(j + 1) {
                    events.push(write(file, Reach::Tree));
                }
            }
            "-exec" | "-execdir" | "-ok" | "-okdir" => {
                let inner: Vec<Word> = args[j + 1..]
                    .iter()
                    .take_while(|w| w.text != ";" && w.text != "+" && w.text != "\\;")
                    .cloned()
                    .collect();
                if let Some(p) = inner.first() {
                    let base = p.text.rsplit('/').next().unwrap_or(&p.text);
                    deletes |= FIND_WRITERS.contains(&base);
                }
                let literal: Vec<Word> = inner.into_iter().filter(|w| w.text != "{}").collect();
                segment_events(&literal, false, false, home, depth + 1, events);
            }
            _ => {}
        }
    }
    if deletes {
        events.extend(starts.iter().map(|w| write(w, Reach::Tree)));
    }
}

fn xargs_events(args: &[Word], home: Option<&str>, depth: u8, events: &mut Vec<Event>) {
    let mut i = 0;
    while i < args.len() {
        let t = args[i].text.as_str();
        if t == "--" {
            i += 1;
            break;
        }
        if !t.starts_with('-') {
            break;
        }
        let takes_value = matches!(
            t,
            "-I" | "-n" | "-P" | "-L" | "-d" | "-E" | "-s" | "-a" | "-J" | "-R"
        );
        i += if takes_value { 2 } else { 1 };
    }
    if i < args.len() {
        segment_events(&args[i..], false, false, home, depth + 1, events);
    }
}

struct Builder {
    bytes: Vec<u8>,
    bare: Vec<bool>,
    started: bool,
    digits_only: bool,
}

impl Builder {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bare: Vec::new(),
            started: false,
            digits_only: true,
        }
    }
    fn push(&mut self, b: u8, bare: bool) {
        self.started = true;
        if !(bare && b.is_ascii_digit()) {
            self.digits_only = false;
        }
        self.bytes.push(b);
        self.bare.push(bare);
    }
    fn push_str(&mut self, s: &str, bare: bool) {
        for &b in s.as_bytes() {
            self.push(b, bare);
        }
    }
    fn take(&mut self) -> Option<Vec<Word>> {
        if !self.started {
            return None;
        }
        let words = expand_braces(&self.bytes, &self.bare)
            .into_iter()
            .map(|(bytes, bare)| Word {
                glob: bytes
                    .iter()
                    .zip(&bare)
                    .any(|(b, bare)| *bare && matches!(b, b'*' | b'?' | b'[')),
                text: String::from_utf8_lossy(&bytes).into_owned(),
            })
            .collect();
        *self = Self::new();
        Some(words)
    }
}

type Bytes = (Vec<u8>, Vec<bool>);

// Not cut off silently past MAX_BRACE_WORDS, nor expanded past
// MAX_BRACE_GROUPS: the word is judged as well with each group read as `*`,
// so a protected name past the cut is still matched as a glob.
fn expand_braces(bytes: &[u8], bare: &[bool]) -> Vec<Bytes> {
    let groups = bytes
        .iter()
        .zip(bare)
        .filter(|(b, bare)| **bare && **b == b'{')
        .count();
    let mut out = if groups > MAX_BRACE_GROUPS {
        vec![(bytes.to_vec(), bare.to_vec())]
    } else {
        brace_expand(bytes, bare)
    };
    if groups > MAX_BRACE_GROUPS || out.len() >= MAX_BRACE_WORDS {
        out.push((bytes.to_vec(), bare.to_vec()));
        out.push(braces_as_stars(bytes, bare));
    }
    out
}

fn braces_as_stars(bytes: &[u8], bare: &[bool]) -> Bytes {
    let (mut out, mut marks) = (Vec::new(), Vec::new());
    let mut depth = 0usize;
    for (&b, &m) in bytes.iter().zip(bare) {
        if m && b == b'{' {
            if depth == 0 {
                out.push(b'*');
                marks.push(true);
            }
            depth += 1;
        } else if m && b == b'}' && depth > 0 {
            depth -= 1;
        } else if depth == 0 {
            out.push(b);
            marks.push(m);
        }
    }
    (out, marks)
}

fn brace_expand(bytes: &[u8], bare: &[bool]) -> Vec<Bytes> {
    let Some(open) = (0..bytes.len()).find(|&i| bare[i] && bytes[i] == b'{') else {
        return vec![(bytes.to_vec(), bare.to_vec())];
    };
    let mut depth = 0;
    let mut commas = Vec::new();
    let mut close = None;
    for i in open..bytes.len() {
        if !bare[i] {
            continue;
        }
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            b',' if depth == 1 => commas.push(i),
            _ => {}
        }
    }
    let (Some(close), false) = (close, commas.is_empty()) else {
        let mut tail = brace_expand(&bytes[open + 1..], &bare[open + 1..]);
        for (b, m) in &mut tail {
            b.insert(0, b'{');
            m.insert(0, true);
        }
        return tail
            .into_iter()
            .map(|(b, m)| {
                (
                    [&bytes[..open], &b[..]].concat(),
                    [&bare[..open], &m[..]].concat(),
                )
            })
            .collect();
    };
    let mut out = Vec::new();
    let mut from = open + 1;
    for &end in commas.iter().chain(std::iter::once(&close)) {
        let joined_bytes = [&bytes[..open], &bytes[from..end], &bytes[close + 1..]].concat();
        let joined_bare = [&bare[..open], &bare[from..end], &bare[close + 1..]].concat();
        out.extend(brace_expand(&joined_bytes, &joined_bare));
        if out.len() >= MAX_BRACE_WORDS {
            out.truncate(MAX_BRACE_WORDS);
            break;
        }
        from = end + 1;
    }
    out
}

struct Lexer<'a> {
    text: &'a str,
    b: &'a [u8],
    home: Option<&'a str>,
    out: Vec<Lexed>,
    word: Builder,
    heredocs: Vec<(String, bool)>,
    expect_delimiter: Option<bool>,
}

fn lex(text: &str, home: Option<&str>) -> Vec<Lexed> {
    let mut lexer = Lexer {
        text,
        b: text.as_bytes(),
        home,
        out: Vec::new(),
        word: Builder::new(),
        heredocs: Vec::new(),
        expect_delimiter: None,
    };
    lexer.run();
    lexer.out
}

impl Lexer<'_> {
    fn end_word(&mut self) {
        let Some(words) = self.word.take() else {
            return;
        };
        if let Some(strip) = self.expect_delimiter.take()
            && let Some(first) = words.first()
            && format!("<<{}", first.text) != crate::unwrap::HEREDOC_MARK
        {
            self.heredocs.push((first.text.clone(), strip));
        }
        self.out.extend(words.into_iter().map(Lexed::Word));
    }

    fn separator(&mut self, and: bool) {
        self.separator_of(and, false);
    }

    fn separator_of(&mut self, and: bool, or: bool) {
        self.end_word();
        self.out.push(Lexed::Separator {
            and,
            or,
            pipe: false,
        });
    }

    // `close` is past the `)` that ends the group, or the end of the text
    // when nothing closes it: the last byte is then part of the command.
    fn nested_group(&mut self, from: usize, close: usize) {
        let to = if self.b.get(close.wrapping_sub(1)) == Some(&b')') {
            close - 1
        } else {
            close
        };
        self.nested(from, to);
    }

    fn nested(&mut self, from: usize, to: usize) {
        let Some(inner) = self.text.get(from.min(to)..to) else {
            return;
        };
        if !inner.trim().is_empty() {
            self.out.push(Lexed::Nested(inner.to_string()));
        }
    }

    // A substitution inside a word that is not itself read as a command —
    // `${x:-$(…)}`, `$(( $(…) ))`, `x=( $(…) )` — is read as one.
    fn nested_within(&mut self, from: usize, to: usize) {
        let b = self.b;
        let mut i = from;
        while i < to.min(b.len()) {
            if b[i] == b'$' && b.get(i + 1) == Some(&b'(') && b.get(i + 2) != Some(&b'(') {
                let close = skip_group(b, i + 1);
                self.nested_group(i + 2, close);
                i = close;
            } else if b[i] == b'`' {
                let close = skip_backquote(b, i + 1);
                self.nested(i + 1, close.saturating_sub(1).min(b.len()));
                i = close;
            } else {
                i += 1;
            }
        }
    }

    // A body that was not set aside as data is read twice: each line as a
    // command of its own, so a quote in one line cannot hide the rest, and
    // the body whole, so a quote or a `\` that spans lines is followed.
    fn heredoc_bodies(&mut self, mut i: usize) -> usize {
        for (delimiter, strip) in std::mem::take(&mut self.heredocs) {
            let start = i;
            let mut body_end = self.b.len();
            while i < self.b.len() {
                let end = self.b[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(self.b.len(), |p| i + p);
                let line = &self.text[i..end];
                i = (end + 1).min(self.b.len());
                let compared = if strip {
                    line.trim_start_matches('\t')
                } else {
                    line
                };
                if compared == delimiter {
                    body_end = end - line.len();
                    break;
                }
                if !line.trim().is_empty() {
                    self.out.push(Lexed::Nested(line.to_string()));
                    self.separator(false);
                }
            }
            self.nested(start, body_end.max(start));
            self.separator(false);
        }
        i
    }

    fn run(&mut self) {
        let (b, text) = (self.b, self.text);
        let mut i = 0;
        while i < b.len() {
            let c = b[i];
            match c {
                b' ' | b'\t' => {
                    self.end_word();
                    i += 1;
                }
                b'\n' | b'\r' => {
                    self.separator(false);
                    i = self.heredoc_bodies(i + 1);
                }
                b';' => {
                    self.separator(false);
                    i += 1;
                }
                b')' => {
                    if matches!(self.out.last(), Some(Lexed::Open)) && !self.word.started {
                        self.out.push(Lexed::Unsafe);
                    }
                    self.separator(false);
                    self.out.push(Lexed::Close);
                    i += 1;
                }
                b'(' => {
                    // Not a separator in `x=( a b )`: an array's words would
                    // be read as a command.
                    if self.word.bytes.last() == Some(&b'=') {
                        let close = skip_group(b, i);
                        self.nested_within(i + 1, close);
                        self.word.push_str(text.get(i..close).unwrap_or(""), false);
                        i = close;
                    } else {
                        self.separator(false);
                        self.out.push(Lexed::Open);
                        i += 1;
                    }
                }
                b'|' => {
                    let or = b.get(i + 1) == Some(&b'|');
                    self.end_word();
                    self.out.push(Lexed::Separator {
                        and: false,
                        or,
                        pipe: !or,
                    });
                    i += if matches!(b.get(i + 1), Some(b'|' | b'&')) {
                        2
                    } else {
                        1
                    };
                }
                b'&' if b.get(i + 1) == Some(&b'>') => {
                    self.end_word();
                    let len = redirect_len(&b[i..]);
                    self.out.push(Lexed::Redirect(text[i..i + len].to_string()));
                    i += len;
                }
                b'&' => {
                    let and = b.get(i + 1) == Some(&b'&');
                    self.separator(and);
                    i += if and { 2 } else { 1 };
                }
                b'<' | b'>' if b.get(i + 1) == Some(&b'(') => {
                    let close = skip_group(b, i + 1);
                    self.nested_group(i + 2, close);
                    self.word.push_str(text.get(i..close).unwrap_or(""), false);
                    i = close;
                }
                b'<' | b'>' => {
                    if self.word.started && !self.word.digits_only && !is_fd_name(&self.word.bytes)
                    {
                        self.end_word();
                    } else {
                        self.word = Builder::new();
                    }
                    let len = redirect_len(&b[i..]);
                    let op = &text[i..i + len];
                    if op.starts_with("<<") && !op.starts_with("<<<") {
                        self.expect_delimiter = Some(op.ends_with('-'));
                    }
                    self.out.push(Lexed::Redirect(op.to_string()));
                    i += len;
                }
                b'#' if !self.word.started => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
                b'\\' => {
                    if let Some(&n) = b.get(i + 1)
                        && n != b'\n'
                    {
                        self.word.push(n, false);
                    }
                    i += 2;
                }
                b'\'' => {
                    let close = b[i + 1..]
                        .iter()
                        .position(|&x| x == b'\'')
                        .map_or(b.len(), |p| i + 1 + p);
                    self.word.push_str(&text[i + 1..close], false);
                    self.word.started = true;
                    i = close + 1;
                }
                b'"' => {
                    i = self.double_quoted(i + 1);
                    self.word.started = true;
                }
                b'$' if b.get(i + 1) == Some(&b'\'') => {
                    let mut j = i + 2;
                    while j < b.len() && b[j] != b'\'' {
                        if b[j] == b'\\' {
                            j += 1;
                        }
                        if let Some(&x) = b.get(j) {
                            self.word.push(x, false);
                        }
                        j += 1;
                    }
                    self.word.started = true;
                    i = j + 1;
                }
                b'$' => i = self.dollar(i),
                b'`' => i = self.backquoted(i),
                b'~' if (!self.word.started
                    || matches!(self.word.bytes.last(), Some(b'=' | b':')))
                    && b.get(i + 1).is_none_or(|n| {
                        matches!(n, b'/' | b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b')')
                    }) =>
                {
                    match self.home {
                        Some(h) => self.word.push_str(h, false),
                        None => self.word.push(b'~', false),
                    }
                    i += 1;
                }
                _ => {
                    self.word.push(c, true);
                    i += 1;
                }
            }
        }
        self.end_word();
    }

    fn backquoted(&mut self, i: usize) -> usize {
        let close = skip_backquote(self.b, i + 1);
        self.nested(i + 1, close.saturating_sub(1));
        self.word
            .push_str(&self.text[i..close.min(self.b.len())], false);
        close
    }

    fn double_quoted(&mut self, mut i: usize) -> usize {
        let b = self.b;
        while i < b.len() && b[i] != b'"' {
            match b[i] {
                b'\\' if matches!(b.get(i + 1), Some(b'$' | b'`' | b'"' | b'\\' | b'\n')) => {
                    if b[i + 1] != b'\n' {
                        self.word.push(b[i + 1], false);
                    }
                    i += 2;
                }
                b'$' => i = self.dollar(i),
                b'`' => i = self.backquoted(i),
                c => {
                    self.word.push(c, false);
                    i += 1;
                }
            }
        }
        i + 1
    }

    // Not dropped when it is not `$HOME`: any other expansion is kept as
    // written, so the protected names next to it are still compared.
    fn dollar(&mut self, i: usize) -> usize {
        let (b, text) = (self.b, self.text);
        let rest = &text[i + 1..];
        let name_end = rest
            .bytes()
            .position(|c| !(c.is_ascii_alphanumeric() || c == b'_'))
            .unwrap_or(rest.len());
        if let Some(h) = self.home {
            if &rest[..name_end] == "HOME" {
                self.word.push_str(h, false);
                return i + 1 + name_end;
            }
            if rest.starts_with("{HOME}") {
                self.word.push_str(h, false);
                return i + 7;
            }
        }
        if rest.starts_with('(') {
            let close = skip_group(b, i + 1);
            if rest.starts_with("((") {
                self.nested_within(i + 3, close);
            } else {
                self.nested_group(i + 2, close);
            }
            self.word.push_str(text.get(i..close).unwrap_or(""), false);
            return close;
        }
        if rest.starts_with('{') {
            let close = skip_braces(b, i + 1);
            self.nested_within(i + 2, close);
            self.word.push_str(text.get(i..close).unwrap_or(""), false);
            return close;
        }
        self.word.push(b'$', false);
        i + 1
    }
}

fn is_fd_name(bytes: &[u8]) -> bool {
    bytes.first() == Some(&b'{') && bytes.last() == Some(&b'}')
}

// `>`, `>>`, `>|`, `>!`, `>&`, `>>&`, zsh's `>&|`, `>>&|`, `&>`, `&>>`, `&>|`,
// `&>!`; `<`, `<<`, `<<-`, `<<<`, `<>`, `<&`.
fn redirect_len(rest: &[u8]) -> usize {
    let at = |i: usize| rest.get(i).copied();
    let mut i = usize::from(rest[0] == b'&');
    if at(i) == Some(b'<') {
        i += 1;
        if at(i) == Some(b'<') {
            i += 1;
            if matches!(at(i), Some(b'<' | b'-')) {
                i += 1;
            }
        } else if matches!(at(i), Some(b'>' | b'&')) {
            i += 1;
        }
        return i;
    }
    i += 1;
    if at(i) == Some(b'>') {
        i += 1;
    }
    if at(i) == Some(b'&') && rest[0] != b'&' {
        i += 1;
    }
    if matches!(at(i), Some(b'|' | b'!')) {
        i += 1;
    }
    i
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Command,
    Arithmetic,
    Grouping,
    Double,
    Backquote,
}

// The index past the `)` that closes the `(` at `open`, read as the shell
// reads a command inside it: quotes, nested groups and substitutions,
// arithmetic, comments and heredoc bodies. Past the end when it never closes.
// Not recursive: a crafted nesting would overflow the stack, and a hook that
// crashes decides nothing.
fn skip_group(b: &[u8], open: usize) -> usize {
    let mut stack = vec![Scope::Command];
    let mut i = open + 1;
    let mut heredocs: Vec<(Vec<u8>, bool)> = Vec::new();
    while i < b.len() {
        let Some(&scope) = stack.last() else {
            return i;
        };
        let at = |k: usize| b.get(k).copied();
        match scope {
            Scope::Double => match b[i] {
                b'\\' => i += 2,
                b'"' => {
                    stack.pop();
                    i += 1;
                }
                b'$' if at(i + 1) == Some(b'(') => {
                    let arith = at(i + 2) == Some(b'(');
                    stack.push(if arith {
                        Scope::Arithmetic
                    } else {
                        Scope::Command
                    });
                    i += if arith { 3 } else { 2 };
                }
                b'`' => {
                    stack.push(Scope::Backquote);
                    i += 1;
                }
                _ => i += 1,
            },
            Scope::Backquote => match b[i] {
                b'\\' => i += 2,
                b'`' => {
                    stack.pop();
                    i += 1;
                }
                _ => i += 1,
            },
            Scope::Arithmetic | Scope::Grouping => match b[i] {
                b')' if scope == Scope::Arithmetic && at(i + 1) == Some(b')') => {
                    stack.pop();
                    i += 2;
                }
                b')' => {
                    stack.pop();
                    i += 1;
                }
                b'$' if at(i + 1) == Some(b'(') && at(i + 2) != Some(b'(') => {
                    stack.push(Scope::Command);
                    i += 2;
                }
                b'(' => {
                    stack.push(Scope::Grouping);
                    i += 1;
                }
                _ => i += 1,
            },
            Scope::Command => {
                let at_word_start = i == open + 1
                    || matches!(b[i - 1], b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b'(');
                match b[i] {
                    b'\\' => i += 2,
                    b'\'' => {
                        i = b[i + 1..]
                            .iter()
                            .position(|&x| x == b'\'')
                            .map_or(b.len(), |p| i + 2 + p);
                    }
                    b'$' if at(i + 1) == Some(b'\'') => {
                        i += 2;
                        while i < b.len() && b[i] != b'\'' {
                            i += if b[i] == b'\\' { 2 } else { 1 };
                        }
                        i += 1;
                    }
                    b'"' => {
                        stack.push(Scope::Double);
                        i += 1;
                    }
                    b'`' => {
                        stack.push(Scope::Backquote);
                        i += 1;
                    }
                    b'$' if at(i + 1) == Some(b'(') => {
                        let arith = at(i + 2) == Some(b'(');
                        stack.push(if arith {
                            Scope::Arithmetic
                        } else {
                            Scope::Command
                        });
                        i += if arith { 3 } else { 2 };
                    }
                    b'(' if at_word_start && at(i + 1) == Some(b'(') => {
                        stack.push(Scope::Arithmetic);
                        i += 2;
                    }
                    b'(' => {
                        stack.push(Scope::Command);
                        i += 1;
                    }
                    b')' => {
                        stack.pop();
                        i += 1;
                    }
                    b'#' if at_word_start => {
                        while i < b.len() && b[i] != b'\n' {
                            i += 1;
                        }
                    }
                    b'<' if at(i + 1) == Some(b'<') && at(i + 2) != Some(b'<') => {
                        let strip = at(i + 2) == Some(b'-');
                        let mut j = i + 2 + usize::from(strip);
                        while j < b.len() && matches!(b[j], b' ' | b'\t') {
                            j += 1;
                        }
                        let mut delimiter = Vec::new();
                        while j < b.len()
                            && !matches!(b[j], b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b')')
                        {
                            if !matches!(b[j], b'\'' | b'"' | b'\\') {
                                delimiter.push(b[j]);
                            }
                            j += 1;
                        }
                        heredocs.push((delimiter, strip));
                        i = j;
                    }
                    b'\n' if !heredocs.is_empty() => {
                        let mut j = i + 1;
                        for (delimiter, strip) in std::mem::take(&mut heredocs) {
                            while j < b.len() {
                                let end = b[j..]
                                    .iter()
                                    .position(|&c| c == b'\n')
                                    .map_or(b.len(), |p| j + p);
                                let mut line = &b[j..end];
                                if strip {
                                    while line.first() == Some(&b'\t') {
                                        line = &line[1..];
                                    }
                                }
                                j = end + 1;
                                if line == delimiter.as_slice() {
                                    break;
                                }
                            }
                        }
                        i = j;
                    }
                    _ => i += 1,
                }
            }
        }
        if stack.is_empty() {
            return i.min(b.len());
        }
    }
    b.len()
}

// The index past the `}` that closes the `{` at `open`, with what a
// substitution inside it holds skipped whole.
fn skip_braces(b: &[u8], open: usize) -> usize {
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'$' if b.get(i + 1) == Some(&b'(') => {
                i = skip_group(b, i + 1);
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

fn skip_backquote(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i] != b'`' {
        i += if b[i] == b'\\' { 2 } else { 1 };
    }
    i + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        lex(text, Some("/h"))
            .into_iter()
            .filter_map(|l| match l {
                Lexed::Word(w) => Some(w.text),
                _ => None,
            })
            .collect()
    }

    fn targets(command: &str) -> Vec<String> {
        let mut events = Vec::new();
        collect_events(command, Some("/h"), 0, &mut events);
        let mut out: Vec<String> = Vec::new();
        for e in events {
            if let Event::Write { target, .. } = e
                && !out.contains(&target.text)
            {
                out.push(target.text);
            }
        }
        out
    }

    #[test]
    fn quotes_decide_what_expands() {
        assert_eq!(
            words("echo ~/a '~/a' \"~/a\""),
            ["echo", "/h/a", "~/a", "~/a"]
        );
        assert_eq!(
            words("echo $HOME/a \"$HOME/a\" '$HOME/a' ${HOME}/a"),
            ["echo", "/h/a", "/h/a", "$HOME/a", "/h/a"]
        );
        assert_eq!(words("echo a\\ b \"c d\""), ["echo", "a b", "c d"]);
    }

    #[test]
    fn redirect_targets_are_writes() {
        for (command, expected) in [
            ("echo x >> /h/f", vec!["/h/f"]),
            ("echo x>/h/f", vec!["/h/f"]),
            (">> /h/f echo x", vec!["/h/f"]),
            ("echo \"x\">>/h/f", vec!["/h/f"]),
            ("echo x 2>/h/e >|/h/f", vec!["/h/e", "/h/f"]),
            ("echo x &>/h/f", vec!["/h/f"]),
            ("echo x >&/h/f", vec!["/h/f"]),
            ("cmd {fd}>/h/f", vec!["/h/f"]),
            ("echo x &>| /h/f", vec!["/h/f"]),
            ("echo x >&| /h/f", vec!["/h/f"]),
            ("echo x >>&| /h/f", vec!["/h/f"]),
            ("echo x &>! /h/f", vec!["/h/f"]),
            ("echo x >&! /h/f", vec!["/h/f"]),
        ] {
            assert_eq!(targets(command), expected, "{command:?}");
        }
    }

    #[test]
    fn what_only_reads_or_duplicates_is_no_write() {
        for command in [
            "ls >&2",
            "cmd 2>&1",
            "cmd >&-",
            "cat < /h/f",
            "cat <<EOF\nx\nEOF",
            "echo '>> /h/f'",
            "echo \">> /h/f\"",
            "diff <(cat /h/a) /h/b",
            "cat /h/.omamori/x",
            "git commit -m \"fix /h/.omamori/x\"",
        ] {
            assert_eq!(targets(command), Vec::<String>::new(), "{command:?}");
        }
    }

    #[test]
    fn a_quote_inside_a_substitution_or_a_body_hides_no_later_write() {
        for (command, expected) in [
            (
                "git commit -m \"$(cat <<'EOF'\nDon't stop\nEOF\n)\" && echo x >> /h/f",
                vec!["/h/f"],
            ),
            ("x=$(echo \"it's\"); touch /h/f", vec!["/h/f"]),
            ("x=`echo it\\'s`; touch /h/f", vec!["/h/f"]),
            ("cat <<EOF | wc -l\ndon't\nEOF\ntouch /h/f", vec!["/h/f"]),
            ("x=$(touch /h/f)", vec!["/h/f"]),
            ("tee >(cat > /h/f) < x", vec!["/h/f"]),
            ("bash <<EOF\ntouch /h/f\nEOF", vec!["/h/f"]),
        ] {
            assert_eq!(targets(command), expected, "{command:?}");
        }
    }

    #[test]
    fn programs_write_where_they_write() {
        for (command, expected) in [
            ("tee -a /h/f /h/g", vec!["/h/f", "/h/g"]),
            ("sed -i '' s/a/b/ /h/f", vec!["/h/f"]),
            ("sed -I '' s/a/b/ /h/f", vec!["/h/f"]),
            ("sed -i s/a/b/ /h/f", vec!["/h/f"]),
            ("sed -i.bak -e s/a/b/ /h/f", vec!["/h/f"]),
            ("sed 's|/h/.omamori|x|' /h/f", vec![]),
            ("perl -pi -e 's/a/b/' /h/f", vec!["/h/f"]),
            ("perl -I lib -pi -e 's/a/b/' /h/f", vec!["/h/f"]),
            ("perl -Mstrict -ne 'print' /h/f", vec![]),
            ("yq -i .a=1 /h/f", vec!["/h/f"]),
            ("cp a b /h/d", vec!["/h/d"]),
            ("cp -t /h/d a", vec!["/h/d"]),
            ("cp -t/h/d a", vec!["/h/d"]),
            ("cp -l /h/f x", vec!["/h/f", "x"]),
            ("mv /h/a /h/b", vec!["/h/a", "/h/b"]),
            ("ln -s /h/f x", vec!["x"]),
            ("ln /h/f x", vec!["/h/f", "x"]),
            ("dd if=x of=/h/f", vec!["/h/f"]),
            ("curl -o /h/f https://x", vec!["/h/f"]),
            ("curl -fsSLo /h/f https://x", vec!["/h/f"]),
            ("curl --output=/h/f https://x", vec!["/h/f"]),
            ("curl -D /h/f https://x", vec!["/h/f"]),
            ("wget -qO /h/f https://x", vec!["/h/f"]),
            ("wget -o /h/f https://x", vec!["/h/f"]),
            ("touch /h/f", vec!["/h/f"]),
            ("chmod 600 /h/f", vec!["/h/f"]),
            ("find /h/a -name x -delete", vec!["/h/a"]),
            ("find -L /h/a -exec rm {} +", vec!["/h/a"]),
            ("find /h/a -name x", vec![]),
            ("find . -fprint /h/f", vec!["/h/f"]),
            ("xargs -I{} rm /h/f", vec!["/h/f"]),
            ("sudo tee /h/f", vec!["/h/f"]),
            ("bash -c 'touch /h/f'", vec!["/h/f"]),
            ("touch /h/{a,b}", vec!["/h/a", "/h/b"]),
        ] {
            assert_eq!(targets(command), expected, "{command:?}");
        }
    }

    #[test]
    fn a_write_is_found_however_the_shell_spells_around_it() {
        for (command, expected) in [
            (
                "echo x > /h/.omamori/log-$(date +%s)",
                "/h/.omamori/log-$(date +%s)",
            ),
            ("bash <<'EOF'\necho \"a\nb\" > /h/f\nEOF", "/h/f"),
            ("bash <<'EOF'\ntouch \\\n /h/f\nEOF", "/h/f"),
            ("x=$(\necho $(( 1 << 4 ))\n)\ntouch /h/f", "/h/f"),
            ("echo ${x:-$(touch /h/f)}", "/h/f"),
            ("echo $(( $(touch /h/f) ))", "/h/f"),
            ("x=( $(touch /h/f) )", "/h/f"),
            ("chmod -x /h/f", "/h/f"),
            ("chmod -R -w /h/f", "/h/f"),
        ] {
            assert!(
                targets(command).iter().any(|t| t == expected),
                "{command:?}: {:?}",
                targets(command)
            );
        }
        assert_eq!(targets("chmod 600 /h/f"), ["/h/f"]);
    }

    #[test]
    fn a_crafted_command_neither_crashes_nor_stalls_the_reader() {
        let deep = format!(
            "echo {}x{}; touch /h/f",
            "$(".repeat(50_000),
            ")".repeat(50_000)
        );
        let _ = targets(&deep);
        let _ = targets("x=$(echo é");
        let _ = targets(&format!("touch /h/{}", "{a,b}".repeat(40)));
        let cds = "cd a && make && cd .. ; ".repeat(40);
        let started = std::time::Instant::now();
        let _ = targets(&format!("{cds}touch /h/f"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_brace_past_the_cut_is_judged_as_written() {
        let many: Vec<String> = (0..70).map(|i| format!("a{i}")).collect();
        let command = format!("touch {{{},/h/.omamori/x}}", many.join(","));
        assert!(
            targets(&command)
                .iter()
                .any(|t| t.contains("/h/.omamori/x"))
        );
    }

    #[test]
    fn a_glob_reaches_what_it_matches_and_what_is_below_it() {
        let p = Path::new;
        assert!(glob_reaches(
            p("/h/.l*/share/omamori/*"),
            p("/h/.local/share/omamori/audit.jsonl")
        ));
        assert!(glob_reaches(p("/h/.omamori/*"), p("/h/.omamori")));
        assert!(glob_reaches(
            p("/h/.c?nfig"),
            p("/h/.config/omamori/config.toml")
        ));
        assert!(!glob_reaches(p("/h/proj/*.pyc"), p("/h/.omamori")));
        assert!(!glob_reaches(p("/h/*"), p("/h/.omamori")));
        assert!(component_matches(b"[a-c]x", b"bx"));
        assert!(!component_matches(b"[!a-c]x", b"bx"));
        assert!(!component_matches(
            &[b'*'; 40].iter().chain(b"b").copied().collect::<Vec<_>>(),
            &[b'a'; 4000]
        ));
    }
}
