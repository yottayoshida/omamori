use std::borrow::Cow;
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Heredoc {
    pub(crate) operator: Range<usize>,
    pub(crate) body: Range<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ctx {
    Single,
    Double,
    AnsiC,
    Backtick,
    Subst,
    Group,
    Arith,
    Param,
    Bracket,
    // In `[[ … ]]` a `(` is not a group, nor a `#` a comment.
    Cond,
}

enum Step {
    Next(usize),
    Comment(usize),
    Heredoc,
    NestedHeredoc,
    TopNewline,
    Continuation,
    Unbalanced,
}

struct Tracker {
    stack: Vec<Ctx>,
    word_start: bool,
}

impl Tracker {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            word_start: true,
        }
    }

    fn top(&self) -> Option<Ctx> {
        self.stack.last().copied()
    }

    fn at_command_level(&self) -> bool {
        self.stack.iter().all(|c| *c == Ctx::Group)
    }

    fn close(&mut self) {
        self.stack.pop();
        self.word_start = false;
    }

    // A `$'…'` inside another quote is not rewritten: the word splitter does
    // not nest quotes.
    fn outside_splitter_quotes(&self) -> bool {
        !self
            .stack
            .iter()
            .any(|c| matches!(c, Ctx::Single | Ctx::Double | Ctx::AnsiC))
    }

    fn step(&mut self, bytes: &[u8], i: usize) -> Step {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();
        let top = self.top();
        match top {
            Some(Ctx::Single) => {
                if b == b'\'' {
                    self.close();
                }
                return Step::Next(i + 1);
            }
            Some(Ctx::AnsiC) | Some(Ctx::Backtick) => {
                let close = if top == Some(Ctx::AnsiC) { b'\'' } else { b'`' };
                if b == b'\\' {
                    return Step::Next(i + 2);
                }
                if b == close {
                    self.close();
                }
                return Step::Next(i + 1);
            }
            Some(Ctx::Double) => {
                return match b {
                    b'\\' => Step::Next(i + 2),
                    b'"' => {
                        self.close();
                        Step::Next(i + 1)
                    }
                    b'$' if next == Some(b'\'') => Step::Next(i + 1),
                    b'$' | b'`' => Step::Next(open_expansion(bytes, i, &mut self.stack)),
                    _ => Step::Next(i + 1),
                };
            }
            Some(Ctx::Arith) if b == b')' && next == Some(b')') => {
                self.close();
                return Step::Next(i + 2);
            }
            Some(Ctx::Param) if b == b'}' => {
                self.close();
                return Step::Next(i + 1);
            }
            Some(Ctx::Bracket) if b == b']' => {
                self.close();
                return Step::Next(i + 1);
            }
            Some(Ctx::Cond) if b == b']' && next == Some(b']') => {
                self.close();
                return Step::Next(i + 2);
            }
            Some(Ctx::Cond) if matches!(b, b'(' | b')' | b'#') => {
                self.word_start = false;
                return Step::Next(i + 1);
            }
            _ => {}
        }

        match b {
            // A `\` and a newline vanish in the shell, and the word state
            // before them carries on; any other escape is part of a word.
            b'\\' if next == Some(b'\n') => {
                if top.is_none() {
                    Step::Continuation
                } else {
                    Step::Next(i + 2)
                }
            }
            b'\\' => {
                self.word_start = false;
                Step::Next(i + 2)
            }
            b'[' if self.word_start && next == Some(b'[') => {
                self.stack.push(Ctx::Cond);
                Step::Next(i + 2)
            }
            b'\'' => {
                self.stack.push(Ctx::Single);
                self.word_start = false;
                Step::Next(i + 1)
            }
            b'"' => {
                self.stack.push(Ctx::Double);
                self.word_start = false;
                Step::Next(i + 1)
            }
            b'$' | b'`' => {
                self.word_start = false;
                Step::Next(open_expansion(bytes, i, &mut self.stack))
            }
            b'(' => {
                let arith = self.word_start && next == Some(b'(');
                self.stack.push(if arith { Ctx::Arith } else { Ctx::Group });
                self.word_start = true;
                Step::Next(i + if arith { 2 } else { 1 })
            }
            b')' => match top {
                // After a group the shell begins a new word; after a
                // substitution the word goes on (`$(date)#x` is one word).
                Some(Ctx::Group) => {
                    self.stack.pop();
                    self.word_start = true;
                    Step::Next(i + 1)
                }
                Some(Ctx::Subst) => {
                    self.close();
                    Step::Next(i + 1)
                }
                _ => {
                    self.word_start = true;
                    Step::Unbalanced
                }
            },
            b'#' if self.word_start && !matches!(top, Some(Ctx::Arith) | Some(Ctx::Param)) => {
                let end = bytes[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(bytes.len(), |n| i + n);
                Step::Comment(end)
            }
            b'<' if next == Some(b'<') => {
                self.word_start = true;
                if bytes.get(i + 2) == Some(&b'<') {
                    Step::Next(i + 3)
                } else if matches!(
                    top,
                    Some(Ctx::Arith) | Some(Ctx::Param) | Some(Ctx::Bracket)
                ) {
                    Step::Next(i + 2)
                } else if top.is_none() {
                    Step::Heredoc
                } else {
                    Step::NestedHeredoc
                }
            }
            b'\n' => {
                self.word_start = true;
                if top.is_none() {
                    Step::TopNewline
                } else {
                    Step::Next(i + 1)
                }
            }
            _ => {
                self.word_start = matches!(b, b' ' | b'\t' | b';' | b'&' | b'|' | b'<' | b'>');
                Step::Next(i + 1)
            }
        }
    }
}

struct Pending {
    operator: Range<usize>,
    delimiter: String,
    strip_tabs: bool,
    quoted: bool,
}

// Not one body at a time: the shell reads bodies one after another, so one
// unsure body makes every body unsure.
pub(crate) fn certain_heredocs(text: &str) -> Option<Vec<Heredoc>> {
    let bytes = text.as_bytes();
    let mut tracker = Tracker::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match tracker.step(bytes, i) {
            Step::Next(n) | Step::Comment(n) => i = n,
            Step::Heredoc => {
                let (delimiter, quoted, strip_tabs, end) = read_operator(bytes, i)?;
                pending.push(Pending {
                    operator: i..end,
                    delimiter,
                    strip_tabs,
                    quoted,
                });
                i = end;
            }
            // Not followed: where a heredoc's body ends inside a substitution or
            // a group, or after a `)` that closes nothing, so none is certain.
            Step::NestedHeredoc | Step::Unbalanced => return None,
            Step::Continuation => {
                if !pending.is_empty() {
                    return None;
                }
                i += 2;
            }
            Step::TopNewline => {
                i += 1;
                if !pending.is_empty() {
                    i = read_bodies(text, i, &mut pending, &mut found)?;
                }
            }
        }
    }
    (tracker.stack.is_empty() && pending.is_empty()).then_some(found)
}

// Not the shell's quoting: normalize and the word splitter know `'`, `"` and
// `$'…'` with `\` escapes, never nested.
struct PlainQuotes {
    single: bool,
    double: bool,
    ansi: bool,
    escaped: bool,
    after_dollar: bool,
    between_words: bool,
}

impl PlainQuotes {
    fn new() -> Self {
        Self {
            single: false,
            double: false,
            ansi: false,
            escaped: false,
            after_dollar: false,
            between_words: true,
        }
    }

    fn comment_starts_here(&self) -> bool {
        !self.single && !self.double && !self.ansi && !self.escaped && self.between_words
    }

    fn advance(&mut self, c: u8) {
        if self.escaped {
            self.escaped = false;
            self.after_dollar = false;
            // A `\` and a newline vanish; the word state before them holds.
            if c != b'\n' {
                self.between_words = false;
            }
            return;
        }
        if self.single {
            self.single = c != b'\'';
            return;
        }
        if self.ansi || self.double {
            match c {
                b'\\' => self.escaped = true,
                b'\'' if self.ansi => self.ansi = false,
                b'"' if self.double => self.double = false,
                _ => {}
            }
            return;
        }
        if c == b'\\' {
            self.escaped = true;
            self.after_dollar = false;
            return;
        }
        match c {
            b'\'' if self.after_dollar => self.ansi = true,
            b'\'' => self.single = true,
            b'"' => self.double = true,
            _ => {}
        }
        self.after_dollar = c == b'$';
        self.between_words = c.is_ascii_whitespace() || matches!(c, b';' | b'|' | b'&');
    }
}

// Never removes anything, only adds a `\`: a misreading here then makes more
// of the text visible, never less.
pub(crate) fn protect_hashes(text: &str) -> Cow<'_, str> {
    if !text.contains('#') {
        return Cow::Borrowed(text);
    }
    let bytes = text.as_bytes();
    let mut tracker = Tracker::new();
    let mut plain = PlainQuotes::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut out: Vec<u8> = Vec::with_capacity(text.len() + 8);
    let mut changed = false;
    let mut i = 0;
    let copy = |out: &mut Vec<u8>, plain: &mut PlainQuotes, from: usize, to: usize| {
        for &c in &bytes[from..to] {
            plain.advance(c);
            out.push(c);
        }
    };
    while i < bytes.len() {
        let in_shell = matches!(tracker.top(), None | Some(Ctx::Subst) | Some(Ctx::Group));
        if bytes[i] == b'\n' && in_shell && !pending.is_empty() {
            tracker.step(bytes, i);
            copy(&mut out, &mut plain, i, i + 1);
            i += 1;
            match read_bodies(text, i, &mut pending, &mut Vec::new()) {
                Some(end) => {
                    copy(&mut out, &mut plain, i, end);
                    i = end;
                }
                None => break,
            }
            continue;
        }
        let next = match tracker.step(bytes, i) {
            Step::Next(n) => {
                for &c in &bytes[i..n.min(bytes.len())] {
                    if c == b'#' && plain.comment_starts_here() {
                        out.push(b'\\');
                        changed = true;
                    }
                    plain.advance(c);
                    out.push(c);
                }
                i = n.min(bytes.len());
                continue;
            }
            Step::Comment(end) => end,
            Step::Heredoc | Step::NestedHeredoc => match read_operator(bytes, i) {
                Some((delimiter, quoted, strip_tabs, end)) => {
                    pending.push(Pending {
                        operator: i..end,
                        delimiter,
                        strip_tabs,
                        quoted,
                    });
                    end
                }
                None => break,
            },
            Step::Continuation => i + 2,
            Step::TopNewline => i + 1,
            Step::Unbalanced => break,
        };
        let next = next.min(bytes.len());
        copy(&mut out, &mut plain, i, next);
        i = next;
    }
    if !changed {
        return Cow::Borrowed(text);
    }
    out.extend_from_slice(&bytes[i.min(bytes.len())..]);
    Cow::Owned(
        String::from_utf8(out)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
    )
}

// Never fails: what cannot be followed is read on as plain text, so the
// rules still see it.
pub(crate) fn lenient_words(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut tracker = Tracker::new();
    let mut nested: Vec<Pending> = Vec::new();
    let mut bodies: Vec<Pending> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word: Vec<u8> = Vec::new();
    let finish = |word: &mut Vec<u8>, words: &mut Vec<String>| {
        if !word.is_empty() {
            words.push(String::from_utf8_lossy(word).into_owned());
            word.clear();
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let top = tracker.top();
        let level = tracker.at_command_level();
        if b == b'\n'
            && !level
            && matches!(top, Some(Ctx::Subst) | Some(Ctx::Group))
            && !nested.is_empty()
        {
            tracker.step(bytes, i);
            word.push(b);
            i += 1;
            // Not to the end of the text when a body is not closed: that would
            // hide every line after it.
            if let Some(end) = read_bodies(text, i, &mut nested, &mut Vec::new()) {
                word.extend_from_slice(&bytes[i..end]);
                i = end;
            }
            continue;
        }
        if level {
            let separator = match (b, bytes.get(i + 1)) {
                (b'&', Some(b'&')) => Some(("&&", 2)),
                (b'|', Some(b'|')) => Some(("||", 2)),
                (b'|', Some(b'&')) => Some(("|", 2)),
                (b'&', Some(b'>')) => None,
                (b'&', _) if operator_char_before(bytes, i, b"<>") => None,
                (b'|', _) if clobber_bar(bytes, i) => None,
                (b'&', _) => Some(("&", 1)),
                (b'|', _) => Some(("|", 1)),
                (b';', _) | (b'\n', _) => Some((";", 1)),
                _ => None,
            };
            if let Some((separator, len)) = separator {
                finish(&mut word, &mut words);
                words.push(separator.to_string());
                tracker.step(bytes, i);
                i += len;
                if b == b'\n' {
                    i = body_lines_as_commands(text, i, &mut bodies, &mut words);
                }
                continue;
            }
            if matches!(b, b' ' | b'\t' | b'\r') {
                finish(&mut word, &mut words);
                tracker.step(bytes, i);
                i += 1;
                continue;
            }
        }
        let depth = tracker.stack.len();
        let step = tracker.step(bytes, i);
        let group_opened =
            b == b'(' && tracker.stack.len() > depth && tracker.top() == Some(Ctx::Group);
        let group_closed = b == b')' && top == Some(Ctx::Group);
        if level && (group_opened || group_closed) {
            finish(&mut word, &mut words);
            i += 1;
            continue;
        }
        let next = match step {
            Step::Comment(end) => {
                i = end;
                continue;
            }
            Step::Heredoc | Step::NestedHeredoc => {
                if let Some(heredoc) = delimiter_as_compared(bytes, i) {
                    if level { &mut bodies } else { &mut nested }.push(heredoc);
                }
                i + 2
            }
            Step::Next(n) => n,
            Step::Continuation => i + 2,
            Step::TopNewline | Step::Unbalanced => i + 1,
        };
        let next = next.min(bytes.len());
        let at_level = level || tracker.at_command_level();
        for (k, &c) in bytes[i..next].iter().enumerate() {
            let escaped = k > 0 && bytes[i + k - 1] == b'\\';
            let quote_mark = at_level && matches!(c, b'\'' | b'"') && !escaped;
            let escape_mark = level && k == 0 && c == b'\\';
            let ansi_mark = level && k == 0 && c == b'$' && bytes.get(i + 1) == Some(&b'\'');
            let continuation = level && c == b'\n';
            if !(quote_mark || escape_mark || ansi_mark || continuation) {
                word.push(c);
            }
        }
        i = next;
    }
    finish(&mut word, &mut words);
    words
}

// Not limited to plain identifiers as `read_operator` is: a wrong delimiter
// is never found, and only leaves the lines after it read as they were.
fn delimiter_as_compared(bytes: &[u8], i: usize) -> Option<Pending> {
    let mut j = i + 2;
    let strip_tabs = bytes.get(j) == Some(&b'-');
    if strip_tabs {
        j += 1;
    }
    while matches!(bytes.get(j), Some(b' ' | b'\t')) {
        j += 1;
    }
    let mut delimiter = Vec::new();
    let mut quoted = false;
    let mut quote = None;
    while let Some(&c) = bytes.get(j) {
        match (quote, c) {
            (_, b'\n') => break,
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => delimiter.push(c),
            (None, b'\'' | b'"') => {
                quoted = true;
                quote = Some(c);
            }
            (None, b'\\') => {
                quoted = true;
                j += 1;
                if let Some(&escaped) = bytes.get(j) {
                    delimiter.push(escaped);
                }
            }
            (None, b' ' | b'\t' | b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')') => break,
            (None, c) => delimiter.push(c),
        }
        j += 1;
    }
    (!delimiter.is_empty()).then(|| Pending {
        operator: i..j.min(bytes.len()),
        delimiter: String::from_utf8_lossy(&delimiter).into_owned(),
        strip_tabs,
        quoted,
    })
}

// Each line on its own: a quote in one line must not carry past it.
fn body_lines_as_commands(
    text: &str,
    start: usize,
    pending: &mut Vec<Pending>,
    words: &mut Vec<String>,
) -> usize {
    let mut pos = start;
    for heredoc in pending.drain(..) {
        let mut lines = Vec::new();
        let mut at = pos;
        let mut closed = None;
        while at < text.len() {
            let line_end = text[at..].find('\n').map_or(text.len(), |n| at + n);
            let line = &text[at..line_end];
            let after = (line_end + 1).min(text.len());
            let compared = if heredoc.strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line
            };
            if compared == heredoc.delimiter {
                closed = Some(after);
                break;
            }
            lines.push(line);
            at = after;
        }
        // Not to the end of the text when the delimiter never comes: a heredoc
        // set aside as data has left its operator and no body.
        let Some(after) = closed else { continue };
        for line in lines {
            words.extend(lenient_words(line));
            words.push(";".to_string());
        }
        pos = after;
    }
    pos
}

// Moved, not removed: a stdin redirection on a shell after a pipe would go,
// and `x | bash < f` would read as a pipe into a shell.
pub(crate) fn redirects_moved_to_the_end(text: &str, shell: Shell) -> Cow<'_, str> {
    if !text.contains(['<', '>']) {
        return Cow::Borrowed(text);
    }
    let bytes = text.as_bytes();
    let mut tracker = Tracker::new();
    let mut nested: Vec<Pending> = Vec::new();
    let mut bodies: Vec<Pending> = Vec::new();
    let mut commands: Vec<SimpleCommand> = Vec::new();
    let mut current = SimpleCommand::at(0);
    let mut word_begin: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();
        // Nothing inside parentheses moves: a redirection before `<(` would be
        // split from its `(`.
        if tracker.top().is_some() {
            if b == b'\n'
                && matches!(tracker.top(), Some(Ctx::Subst) | Some(Ctx::Group))
                && !nested.is_empty()
            {
                tracker.step(bytes, i);
                i = read_bodies(text, i + 1, &mut nested, &mut Vec::new()).unwrap_or(i + 1);
                continue;
            }
            i = match tracker.step(bytes, i) {
                Step::NestedHeredoc => {
                    nested.extend(delimiter_as_compared(bytes, i));
                    i + 2
                }
                step => step_end(step, i),
            };
            continue;
        }
        // Not a word boundary: the shell drops a `\` and its newline.
        if b == b'\\' && next == Some(b'\n') {
            tracker.step(bytes, i);
            i += 2;
            continue;
        }
        let redirect =
            (matches!(b, b'<' | b'>') && next != Some(b'(')) || (b == b'&' && next == Some(b'>'));
        if redirect {
            // No descriptor for `&>`: bash reads the digits before it as a word.
            let descriptor = word_begin
                .filter(|&w| b != b'&' && is_io_number(&bytes[w..i]))
                .inspect(|_| {
                    current.word_starts.pop();
                });
            let start = descriptor.unwrap_or(i);
            let operator = redirect_operator_len(&bytes[i..], shell);
            let heredoc = bytes[i..].starts_with(b"<<") && !bytes[i..].starts_with(b"<<<");
            let end = match heredoc.then(|| delimiter_as_compared(bytes, i)).flatten() {
                Some(pending) => {
                    let end = pending.operator.end;
                    bodies.push(pending);
                    end
                }
                None => word_end(&mut tracker, bytes, i + operator),
            };
            current.redirects.push(start..end);
            word_begin = None;
            i = end;
            continue;
        }
        let terminator = match (b, next) {
            (b'&', Some(b'&')) | (b'|', Some(b'|')) | (b'|', Some(b'&')) => 2,
            (b';' | b'&' | b'|' | b'\n', _) => 1,
            _ => 0,
        };
        if terminator > 0 {
            current.end = i;
            commands.push(std::mem::replace(&mut current, SimpleCommand::at(i)));
            tracker.step(bytes, i);
            i += terminator;
            if b == b'\n' {
                i = past_bodies(text, i, &mut bodies);
            }
            current.start = i;
            word_begin = None;
            continue;
        }
        if matches!(b, b' ' | b'\t' | b'\r') {
            word_begin = None;
            tracker.step(bytes, i);
            i += 1;
            continue;
        }
        let step = tracker.step(bytes, i);
        // Not past a comment: a redirection moved behind `#` would be lost.
        if let Step::Comment(comment_end) = step {
            current.end = i;
            commands.push(std::mem::replace(
                &mut current,
                SimpleCommand::at(comment_end),
            ));
            word_begin = None;
            i = comment_end;
            continue;
        }
        if word_begin.is_none() {
            word_begin = Some(i);
            current.word_starts.push(i);
        }
        i = step_end(step, i);
    }
    current.end = bytes.len();
    commands.push(current);
    if !commands.iter().any(SimpleCommand::moves) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    let mut pos = 0;
    for command in &commands {
        out.push_str(&text[pos..command.start]);
        if command.moves() {
            let mut at = command.start;
            for redirect in &command.redirects {
                out.push_str(&text[at..redirect.start]);
                at = redirect.end;
            }
            out.push_str(&text[at..command.end]);
            for redirect in &command.redirects {
                out.push(' ');
                out.push_str(&text[redirect.clone()]);
            }
            // Not against what follows: a `#` there would join the last word.
            out.push(' ');
        } else {
            out.push_str(&text[command.start..command.end]);
        }
        pos = command.end;
    }
    out.push_str(&text[pos..]);
    Cow::Owned(out)
}

struct SimpleCommand {
    start: usize,
    end: usize,
    redirects: Vec<Range<usize>>,
    word_starts: Vec<usize>,
}

impl SimpleCommand {
    fn at(start: usize) -> Self {
        Self {
            start,
            end: start,
            redirects: Vec::new(),
            word_starts: Vec::new(),
        }
    }

    fn moves(&self) -> bool {
        self.redirects
            .first()
            .is_some_and(|first| self.word_starts.iter().any(|&w| w > first.start))
    }
}

fn step_end(step: Step, i: usize) -> usize {
    match step {
        Step::Next(n) | Step::Comment(n) => n,
        Step::Heredoc | Step::NestedHeredoc | Step::Continuation => i + 2,
        Step::TopNewline | Step::Unbalanced => i + 1,
    }
}

fn is_io_number(word: &[u8]) -> bool {
    let mut joined = Vec::with_capacity(word.len());
    let mut k = 0;
    while k < word.len() {
        if word[k] == b'\\' && word.get(k + 1) == Some(&b'\n') {
            k += 2;
            continue;
        }
        joined.push(word[k]);
        k += 1;
    }
    let word = joined.as_slice();
    let named = word.len() > 2
        && word[0] == b'{'
        && word[word.len() - 1] == b'}'
        && (word[1].is_ascii_alphabetic() || word[1] == b'_')
        && word[1..word.len() - 1]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_');
    named || (!word.is_empty() && word.iter().all(u8::is_ascii_digit))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shell {
    Zsh,
    Bash,
}

// Not bash as well without a `!`: the two readings would be the same.
pub(crate) fn shells_reading(text: &str) -> &'static [Shell] {
    if text.contains('!') {
        &[Shell::Zsh, Shell::Bash]
    } else {
        &[Shell::Zsh]
    }
}

fn redirect_operator_len(rest: &[u8], shell: Shell) -> usize {
    [
        "&>>|", "&>>!", ">>&|", ">>&!", "&>>", "&>|", "&>!", "<<<", "<<-", ">>&", ">>|", ">>!",
        ">&|", ">&!", "&>", "<<", "<&", "<>", ">>", ">|", ">!", ">&", "<", ">",
    ]
    .iter()
    // The `|` forms stay for bash: it rejects them, so nothing it runs is misread.
    .filter(|op| shell == Shell::Zsh || !op.ends_with('!'))
    .find(|op| rest.starts_with(op.as_bytes()))
    .map_or(1, |op| op.len())
}

pub(crate) fn clobber_bar(bytes: &[u8], i: usize) -> bool {
    operator_char_before(bytes, i, b">")
        || (operator_char_before(bytes, i, b"&") && operator_char_before(bytes, i - 1, b">"))
}

pub(crate) fn operator_char_before(bytes: &[u8], i: usize, chars: &[u8]) -> bool {
    i > 0
        && chars.contains(&bytes[i - 1])
        && bytes[..i - 1]
            .iter()
            .rev()
            .take_while(|&&c| c == b'\\')
            .count()
            % 2
            == 0
}

fn word_end(tracker: &mut Tracker, bytes: &[u8], mut i: usize) -> usize {
    loop {
        match (bytes.get(i), bytes.get(i + 1)) {
            (Some(b' ' | b'\t'), _) => {
                tracker.step(bytes, i);
                i += 1;
            }
            (Some(b'\\'), Some(b'\n')) => {
                tracker.step(bytes, i);
                i += 2;
            }
            _ => break,
        }
    }
    while i < bytes.len() {
        if tracker.top().is_none() {
            if matches!(bytes[i], b'<' | b'>') && bytes.get(i + 1) == Some(&b'(') {
                tracker.step(bytes, i);
                tracker.step(bytes, i + 1);
                i += 2;
                continue;
            }
            if matches!(
                bytes[i],
                b' ' | b'\t' | b'\r' | b'\n' | b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')'
            ) {
                break;
            }
        }
        let step = tracker.step(bytes, i);
        i = step_end(step, i);
    }
    i.min(bytes.len())
}

fn past_bodies(text: &str, start: usize, pending: &mut Vec<Pending>) -> usize {
    let mut pos = start;
    for heredoc in pending.drain(..) {
        let mut at = pos;
        while at < text.len() {
            let line_end = text[at..].find('\n').map_or(text.len(), |n| at + n);
            let line = &text[at..line_end];
            let after = (line_end + 1).min(text.len());
            let compared = if heredoc.strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line
            };
            if compared == heredoc.delimiter {
                pos = after;
                break;
            }
            // Not taken as a body: the shell joins a continued line before it
            // compares, so where the body ends is not known.
            if !heredoc.quoted && line.ends_with('\\') {
                break;
            }
            at = after;
        }
    }
    pos
}

// Escapes are kept as written except `\'`: it would end no string in `"…"`.
pub(crate) fn ansi_c_as_double_quoted(text: &str) -> Cow<'_, str> {
    if !text.contains("$'") {
        return Cow::Borrowed(text);
    }
    let bytes = text.as_bytes();
    let mut tracker = Tracker::new();
    let mut out: Vec<u8> = Vec::with_capacity(text.len() + 8);
    let mut i = 0;
    while i < bytes.len() {
        let opening_ansi = bytes[i] == b'$'
            && bytes.get(i + 1) == Some(&b'\'')
            && tracker.outside_splitter_quotes()
            && tracker.top() != Some(Ctx::Backtick);
        let next = match tracker.step(bytes, i) {
            Step::Next(n) | Step::Comment(n) => n,
            Step::Heredoc | Step::NestedHeredoc | Step::Continuation => i + 2,
            Step::TopNewline | Step::Unbalanced => i + 1,
        };
        if !opening_ansi {
            out.extend_from_slice(&bytes[i..next.min(bytes.len())]);
            i = next;
            continue;
        }
        out.push(b'"');
        let mut j = i + 2;
        while j < bytes.len() && bytes[j] != b'\'' {
            match bytes[j] {
                b'\\' if bytes.get(j + 1) == Some(&b'\'') => {
                    out.push(b'\'');
                    j += 2;
                    continue;
                }
                b'\\' => {
                    out.extend_from_slice(&bytes[j..(j + 2).min(bytes.len())]);
                    j += 2;
                    continue;
                }
                b'"' | b'$' | b'`' => {
                    out.push(b'\\');
                    out.push(bytes[j]);
                }
                c => out.push(c),
            }
            j += 1;
        }
        out.push(b'"');
        i = (j + 1).min(bytes.len());
        tracker.stack.pop();
    }
    Cow::Owned(
        String::from_utf8(out)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
    )
}

fn open_expansion(bytes: &[u8], i: usize, stack: &mut Vec<Ctx>) -> usize {
    if bytes[i] == b'`' {
        stack.push(Ctx::Backtick);
        return i + 1;
    }
    match (bytes.get(i + 1), bytes.get(i + 2)) {
        (Some(b'('), Some(b'(')) => {
            stack.push(Ctx::Arith);
            i + 3
        }
        (Some(b'('), _) => {
            stack.push(Ctx::Subst);
            i + 2
        }
        (Some(b'{'), _) => {
            stack.push(Ctx::Param);
            i + 2
        }
        (Some(b'['), _) => {
            stack.push(Ctx::Bracket);
            i + 2
        }
        (Some(b'\''), _) => {
            stack.push(Ctx::AnsiC);
            i + 2
        }
        _ => i + 1,
    }
}

fn read_operator(bytes: &[u8], i: usize) -> Option<(String, bool, bool, usize)> {
    let mut j = i + 2;
    let strip_tabs = bytes.get(j) == Some(&b'-');
    if strip_tabs {
        j += 1;
    }
    while matches!(bytes.get(j), Some(b' ' | b'\t')) {
        j += 1;
    }
    let (word, quoted, end) = match bytes.get(j) {
        Some(&quote @ (b'\'' | b'"')) => {
            let close = bytes[j + 1..].iter().position(|&c| c == quote)? + j + 1;
            (&bytes[j + 1..close], true, close + 1)
        }
        _ => {
            let len = bytes[j..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
                .count();
            (&bytes[j..j + len], false, j + len)
        }
    };
    let identifier = word
        .first()
        .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
        && word.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
    let boundary = matches!(
        bytes.get(end),
        None | Some(b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'<' | b'>' | b')')
    );
    (identifier && boundary).then(|| {
        (
            String::from_utf8_lossy(word).into_owned(),
            quoted,
            strip_tabs,
            end,
        )
    })
}

// A body that continues a line with `\` under an unquoted delimiter is not
// certain: the shell joins those lines before it compares them with the
// delimiter.
fn read_bodies(
    text: &str,
    start: usize,
    pending: &mut Vec<Pending>,
    found: &mut Vec<Heredoc>,
) -> Option<usize> {
    let mut pos = start;
    for heredoc in pending.drain(..) {
        let body_start = pos;
        loop {
            if pos >= text.len() {
                return None;
            }
            let line_end = text[pos..].find('\n').map_or(text.len(), |n| pos + n);
            let line = &text[pos..line_end];
            let after = (line_end + 1).min(text.len());
            let compared = if heredoc.strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line
            };
            if compared == heredoc.delimiter {
                found.push(Heredoc {
                    operator: heredoc.operator,
                    body: body_start..after,
                });
                pos = after;
                break;
            }
            if !heredoc.quoted && line.ends_with('\\') {
                return None;
            }
            pos = after;
        }
    }
    Some(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bodies(text: &str) -> Option<Vec<&str>> {
        certain_heredocs(text).map(|found| found.iter().map(|h| &text[h.body.clone()]).collect())
    }

    #[test]
    fn a_closed_heredoc_with_a_plain_delimiter_is_certain() {
        assert_eq!(
            bodies("cat > f <<'EOF'\na\nb\nEOF\necho done"),
            Some(vec!["a\nb\nEOF\n"])
        );
        assert_eq!(bodies("cat <<EOF\nx\nEOF"), Some(vec!["x\nEOF"]));
        assert_eq!(bodies("cat <<\"EOF\"\nx\nEOF\n"), Some(vec!["x\nEOF\n"]));
        assert_eq!(
            bodies("cat <<-EOF\n\tx\n\tEOF\n"),
            Some(vec!["\tx\n\tEOF\n"])
        );
    }

    #[test]
    fn two_heredocs_on_one_line_are_read_in_order() {
        assert_eq!(
            bodies("bash <<B; cat <<A\nb1\nB\na1\nA\n"),
            Some(vec!["b1\nB\n", "a1\nA\n"])
        );
    }

    #[test]
    fn text_without_a_heredoc_has_none() {
        assert_eq!(bodies("echo hi; cat <<< word"), Some(vec![]));
    }

    #[test]
    fn a_shift_inside_an_expansion_is_not_a_heredoc() {
        assert_eq!(bodies("echo $((1<<2))\nls"), Some(vec![]));
        assert_eq!(bodies("cat /dev/null ${x:1<<1}\nls\n1}"), Some(vec![]));
        assert_eq!(bodies("cat /dev/null $[1<<2]\nls\n2]"), Some(vec![]));
    }

    #[test]
    fn a_heredoc_in_a_comment_is_not_one() {
        assert_eq!(bodies("cat /dev/null # see <<EOF\nls\nEOF"), Some(vec![]));
        assert_eq!(bodies("echo a#b <<EOF\nx\nEOF"), Some(vec!["x\nEOF"]));
    }

    #[test]
    fn a_heredoc_whose_extent_is_unsure_makes_the_whole_text_unsure() {
        for text in [
            "cat <<EOF\nnever closed",
            "cat <<EOF\nb\nE\\\nOF\nls\nEOF",
            "cat <<EOF \\\n| sh\nls\nEOF",
            "cat <<2))\nls",
            "cat <<E'O'F\nx\nEOF",
            "x=$(cat <<EOF\ny\nEOF\n)",
            "(cat <<EOF\nx\nEOF\n)",
            "cat <<EOF\nx\nEOF\r\n",
            "echo )",
            "echo 'unclosed",
        ] {
            assert_eq!(bodies(text), None, "{text:?}");
        }
    }

    #[test]
    fn a_quoted_delimiter_keeps_a_trailing_backslash_as_text() {
        assert_eq!(bodies("cat <<'EOF'\na\\\nEOF\n"), Some(vec!["a\\\nEOF\n"]));
    }

    #[test]
    fn quotes_and_expansions_hide_what_looks_like_an_operator() {
        assert_eq!(bodies("echo '<<EOF'\nls"), Some(vec![]));
        assert_eq!(bodies("echo \"a <<EOF\"\nls"), Some(vec![]));
        assert_eq!(bodies("echo $'\\' <<EOF'\nls"), Some(vec![]));
        assert_eq!(
            bodies("echo \"$(date)\" <<EOF\nx\nEOF\n"),
            Some(vec!["x\nEOF\n"])
        );
    }

    #[test]
    fn non_ascii_text_is_read_by_byte_without_losing_its_place() {
        assert_eq!(
            bodies("cat <<EOF\n日本語\nEOF\n"),
            Some(vec!["日本語\nEOF\n"])
        );
    }

    #[test]
    fn a_hash_the_shell_reads_inside_a_word_gets_a_backslash() {
        for (text, expected) in [
            ("echo `echo a #b` ; ls", "echo `echo a \\#b` ; ls"),
            ("echo $((1 + #x)) ; ls", "echo $((1 + \\#x)) ; ls"),
            ("[[ $x =~ ( #a) ]] ; ls", "[[ $x =~ ( \\#a) ]] ; ls"),
            (
                "msg=\"$(git log -1 --format=\"%s #%h\")\" ; ls",
                "msg=\"$(git log -1 --format=\"%s \\#%h\")\" ; ls",
            ),
        ] {
            assert_eq!(protect_hashes(text), expected, "{text:?}");
        }
    }

    #[test]
    fn a_comment_or_a_hash_inside_a_word_is_left_alone() {
        for text in [
            "# note\ngit push",
            "ls # a ; b\nrm x",
            "echo a#b",
            "echo ${#a[@]}",
            "echo $(date)#x ; ls",
            "diff <(true)#x ; ls",
            "a=(1 2)#x ; ls",
            "echo '# x' \"# y\"",
            "echo $'a # b' ; ls",
            "x=$(echo a # c\n)",
            "ls \\\n# cleanup ; rm x",
        ] {
            assert_eq!(protect_hashes(text), text, "{text:?}");
        }
    }

    #[test]
    fn a_heredoc_body_in_a_substitution_is_read_past() {
        let text = "git commit -m \"$(cat <<'EOF'\nit's\nEOF\n)\" ; echo `a #b`";
        assert_eq!(
            protect_hashes(text),
            "git commit -m \"$(cat <<'EOF'\nit's\nEOF\n)\" ; echo `a \\#b`"
        );
    }

    #[test]
    fn nothing_is_escaped_past_what_cannot_be_followed() {
        assert_eq!(
            protect_hashes("echo ) ; echo `a #b`"),
            "echo ) ; echo `a #b`"
        );
        assert_eq!(
            protect_hashes("cat <<2))\nx\n2))\necho `a #b`"),
            "cat <<2))\nx\n2))\necho `a #b`"
        );
    }

    fn moved(text: &str) -> String {
        let out = redirects_moved_to_the_end(text, Shell::Zsh);
        let mut collapsed = String::new();
        for c in out.chars() {
            if c == ' ' && (collapsed.is_empty() || collapsed.ends_with([' ', '\n'])) {
                continue;
            }
            if c == '\n' && collapsed.ends_with(' ') {
                collapsed.pop();
            }
            collapsed.push(c);
        }
        collapsed.trim_end_matches(' ').to_string()
    }

    #[test]
    fn redirects_move_to_the_end_of_their_command() {
        for (text, expected) in [
            (
                "omamori 2>/dev/null override disable x",
                "omamori override disable x 2>/dev/null",
            ),
            (
                "omamori>/dev/null override x",
                "omamori override x >/dev/null",
            ),
            ("omamori 10>/dev/null x", "omamori x 10>/dev/null"),
            ("omamori {fd}>/dev/null x", "omamori x {fd}>/dev/null"),
            ("omamori <&- x", "omamori x <&-"),
            ("omamori >| f x", "omamori x >| f"),
            ("omamori 2>'-' x", "omamori x 2>'-'"),
            ("omamori 2> \"/dev/null\" x", "omamori x 2> \"/dev/null\""),
            ("omamori <<<x y", "omamori y <<<x"),
            ("a 2>&1 >f b", "a b 2>&1 >f"),
            ("a2>x b", "a2 b >x"),
            ("echo a&>f b", "echo a b &>f"),
            ("a 2>x; b >y c", "a 2>x; b c >y"),
            ("a >x | b <y c && d 2>z e", "a >x | b c <y && d e 2>z"),
            (
                "env 2>/dev/null -i omamori uninstall",
                "env -i omamori uninstall 2>/dev/null",
            ),
            (">f cmd a", "cmd a >f"),
            (
                "2>/dev/null unset CLAUDECODE",
                "unset CLAUDECODE 2>/dev/null",
            ),
            ("10>/dev/null omamori x", "omamori x 10>/dev/null"),
            ("omamori < <(true) x", "omamori x < <(true)"),
            ("omamori 2> >(cat) x", "omamori x 2> >(cat)"),
            ("omamori \\\n2>/dev/null x", "omamori \\\nx 2>/dev/null"),
            ("omamori > \\\n f x", "omamori x > \\\nf"),
            ("omamori 2\\\n>/dev/null x", "omamori x 2\\\n>/dev/null"),
            ("omamori >! f x", "omamori x >! f"),
            ("omamori >>! f x", "omamori x >>! f"),
            ("x 2&>f y", "x 2 y &>f"),
            ("omamori >>| f x", "omamori x >>| f"),
            ("omamori &>! f x", "omamori x &>! f"),
            ("omamori >&| f x", "omamori x >&| f"),
            ("omamori >>&! f x", "omamori x >>&! f"),
            ("omamori &>>| f x", "omamori x &>>| f"),
        ] {
            assert_eq!(moved(text), expected, "{text:?}");
        }
    }

    #[test]
    fn what_the_shell_does_not_read_as_a_redirect_stays() {
        for text in [
            "echo hello 2>/dev/null",
            "echo 'a > b' \"c > d\" e\\>f",
            "echo $((3 > 2)) x",
            "[[ a > b ]] && echo x",
            "diff <(ls a) >(wc) x",
            "echo $(cat <f) x",
            "true & false",
            "cat x | bash < setup.sh",
            "(omamori 2>/dev/null x) >f",
            "cmd >/dev/null 2>&1",
            "cat setup.log | bash < setup.sh # run",
        ] {
            assert!(
                matches!(
                    redirects_moved_to_the_end(text, Shell::Zsh),
                    Cow::Borrowed(_)
                ),
                "{text:?}: {:?}",
                redirects_moved_to_the_end(text, Shell::Zsh)
            );
        }
    }

    #[test]
    fn a_redirection_moves_ahead_of_a_comment_and_keeps_the_blanks_it_follows() {
        assert_eq!(
            redirects_moved_to_the_end("cat > notes.md <<'EOF' x # notes\nbody\nEOF", Shell::Zsh),
            "cat   x  > notes.md <<'EOF' # notes\nbody\nEOF"
        );
        assert_eq!(
            redirects_moved_to_the_end("cmd >f a\\\t", Shell::Zsh),
            "cmd  a\\\t >f "
        );
    }

    #[test]
    fn bash_reads_a_bang_after_a_redirection_as_its_target() {
        let moved = redirects_moved_to_the_end("omamori >! override disable x", Shell::Bash);
        assert_eq!(
            moved.split_whitespace().collect::<Vec<_>>(),
            vec!["omamori", "override", "disable", "x", ">!"]
        );
    }

    #[test]
    fn a_body_whose_delimiter_line_may_be_continued_is_not_taken_as_one() {
        assert_eq!(
            moved("cat <<EOF\nEO\\\nF\nomamori 2>/dev/null x\nEOF"),
            "cat <<EOF\nEO\\\nF\nomamori x 2>/dev/null\nEOF"
        );
        assert_eq!(
            moved("cat <<'EOF'\nEO\\\nEOF\nomamori 2>/dev/null x"),
            "cat <<'EOF'\nEO\\\nEOF\nomamori x 2>/dev/null"
        );
    }

    #[test]
    fn a_heredoc_body_is_left_as_it_is() {
        assert_eq!(
            moved("omamori <<EOF x\nbody 2>/dev/null y\nEOF\nnext 2>/dev/null z"),
            "omamori x <<EOF\nbody 2>/dev/null y\nEOF\nnext z 2>/dev/null"
        );
        assert_eq!(
            moved("cat <<'EOF' >out x\na > b\nEOF"),
            "cat x <<'EOF' >out\na > b\nEOF"
        );
    }

    #[test]
    fn lenient_words_split_where_the_shell_does() {
        assert_eq!(
            lenient_words("true & git push --force; echo 'x"),
            vec!["true", "&", "git", "push", "--force", ";", "echo", "x"]
        );
        assert_eq!(
            lenient_words("echo \"$(echo \"'\")\"; git push --force"),
            vec!["echo", "$(echo \"'\")", ";", "git", "push", "--force"]
        );
        assert_eq!(
            lenient_words("rm \"-rf\" ~/x 'a b'"),
            vec!["rm", "-rf", "~/x", "a b"]
        );
        assert_eq!(
            lenient_words("echo it\\'s $'a\\'b'"),
            vec!["echo", "it's", "a\\'b"]
        );
        assert_eq!(
            lenient_words(
                "git commit -m \"$(cat <<'EOF'\nMeasure 5\" panels\ngit push --force\nEOF\n)\"\nls"
            ),
            vec![
                "git",
                "commit",
                "-m",
                "$(cat <<'EOF'\nMeasure 5\" panels\ngit push --force\nEOF\n)",
                ";",
                "ls"
            ]
        );
        assert_eq!(
            lenient_words("# don't\ngit push --force\necho 'x"),
            vec![";", "git", "push", "--force", ";", "echo", "x"]
        );
    }

    #[test]
    fn lenient_words_split_inside_a_group_as_at_the_top() {
        assert_eq!(
            lenient_words("(cd build && git push --force origin main); echo 'x"),
            vec![
                "cd", "build", "&&", "git", "push", "--force", "origin", "main", ";", "echo", "x"
            ]
        );
        assert_eq!(
            lenient_words("{ (git push --force) }; echo 'x"),
            vec!["{", "git", "push", "--force", "}", ";", "echo", "x"]
        );
        assert_eq!(
            lenient_words("echo $( (a; b) ) 'x"),
            vec!["echo", "$( (a; b) )", "x"]
        );
    }

    #[test]
    fn lenient_words_read_a_heredoc_body_a_line_at_a_time() {
        assert_eq!(
            lenient_words("psql <<'EOF'\n-- don't drop\nSELECT 1;\nEOF\ngit push --force"),
            vec![
                "psql",
                "<<EOF",
                ";",
                "--",
                "dont drop",
                ";",
                "SELECT",
                "1",
                ";",
                ";",
                "git",
                "push",
                "--force"
            ]
        );
        assert_eq!(
            lenient_words("cat <<-'END-MSG'\n\tdon't\n\tEND-MSG\ngit push --force"),
            vec![
                "cat",
                "<<-END-MSG",
                ";",
                "dont",
                ";",
                "git",
                "push",
                "--force"
            ]
        );
        assert_eq!(
            lenient_words("(cat <<EOF\nit's\nEOF\n) ; git push --force"),
            vec![
                "cat", "<<EOF", ";", "its", ";", ";", "git", "push", "--force"
            ]
        );
    }

    #[test]
    fn lenient_words_keep_a_heredoc_body_in_a_substitution_to_its_delimiter() {
        assert_eq!(
            lenient_words(
                "git commit -m \"$(cat <<'END-MSG'\ndon't\nEND-MSG\n)\"\ngit push --force; echo 'x"
            ),
            vec![
                "git",
                "commit",
                "-m",
                "$(cat <<'END-MSG'\ndon't\nEND-MSG\n)",
                ";",
                "git",
                "push",
                "--force",
                ";",
                "echo",
                "x"
            ]
        );
        assert!(
            lenient_words("echo \"$(cat <<EOF\nx\n)\"\ngit push --force")
                .windows(2)
                .any(|w| w == ["push", "--force"])
        );
    }

    #[test]
    fn lenient_words_read_a_heredoc_written_with_the_set_aside_name_as_any_other() {
        assert!(
            lenient_words("psql <<OMAMORI_HEREDOC\ndon't\nOMAMORI_HEREDOC\ngit push --force")
                .windows(2)
                .any(|w| w == ["push", "--force"])
        );
    }

    #[test]
    fn lenient_words_begin_a_nested_body_after_a_newline_outside_quotes() {
        assert!(
            lenient_words("echo \"$(cat <<EOF 'a\nb'\nbody\nEOF\n)\"; git push --force")
                .windows(2)
                .any(|w| w == ["push", "--force"])
        );
    }

    #[test]
    fn lenient_words_read_a_pipe_with_stderr_as_a_pipe() {
        assert_eq!(
            lenient_words("curl x |& bash; echo 'y"),
            vec!["curl", "x", "|", "bash", ";", "echo", "y"]
        );
    }

    #[test]
    fn lenient_words_read_an_escaped_operator_character_as_text() {
        assert_eq!(
            lenient_words("echo \\>| omamori x; echo 'y"),
            vec!["echo", ">", "|", "omamori", "x", ";", "echo", "y"]
        );
    }

    #[test]
    fn lenient_words_keep_a_zsh_clobber_after_a_duplication_as_a_redirect() {
        assert_eq!(
            lenient_words("omamori >&| f x; echo 'y"),
            vec!["omamori", ">&|", "f", "x", ";", "echo", "y"]
        );
    }

    #[test]
    fn lenient_words_keep_a_clobber_and_a_duplication_as_redirects() {
        assert_eq!(
            lenient_words("omamori >| f <&- x; echo 'y"),
            vec!["omamori", ">|", "f", "<&-", "x", ";", "echo", "y"]
        );
    }

    #[test]
    fn an_ansi_c_string_becomes_a_double_quoted_one() {
        assert_eq!(
            ansi_c_as_double_quoted("echo $'a\\'b'; ls"),
            "echo \"a'b\"; ls"
        );
        assert_eq!(
            ansi_c_as_double_quoted("echo $'$x \"q\"'"),
            "echo \"\\$x \\\"q\\\"\""
        );
        assert_eq!(ansi_c_as_double_quoted("echo '$'\"$'\""), "echo '$'\"$'\"");
        let nested = "git commit -m \"$(printf $'a ; b')\"";
        assert_eq!(ansi_c_as_double_quoted(nested), nested);
        assert_eq!(
            shell_words::split(&ansi_c_as_double_quoted("echo $'\\' # ' ; git push")).unwrap(),
            vec!["echo", "' # ", ";", "git", "push"]
        );
    }
}
